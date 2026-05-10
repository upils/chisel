package deb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/blakesmith/ar"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/canonical/chisel/internal/fsutil"
	"github.com/canonical/chisel/internal/strdist"
)

type ExtractOptions struct {
	Package   string
	TargetDir string
	Extract   map[string][]ExtractInfo
	// Create can optionally be set to control the creation of extracted entries.
	// extractInfos is set to the matching entries in Extract, and is nil in cases where
	// the created entry is implicit and unlisted (for example, parent directories).
	Create func(extractInfos []ExtractInfo, options *fsutil.CreateOptions) error
}

type ExtractInfo struct {
	Path     string
	Mode     uint
	Optional bool
	Context  any
}

func getValidOptions(options *ExtractOptions) (*ExtractOptions, error) {
	for extractPath, extractInfos := range options.Extract {
		isGlob := strings.ContainsAny(extractPath, "*?")
		if isGlob {
			for _, extractInfo := range extractInfos {
				if extractInfo.Path != extractPath || extractInfo.Mode != 0 {
					return nil, fmt.Errorf("when using wildcards source and target paths must match: %s", extractPath)
				}
			}
		}
	}

	if options.Create == nil {
		validOpts := *options
		validOpts.Create = func(_ []ExtractInfo, o *fsutil.CreateOptions) error {
			_, err := fsutil.Create(o)
			return err
		}
		return &validOpts, nil
	}

	return options, nil
}

func Extract(pkgReader io.ReadSeeker, options *ExtractOptions) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("cannot extract from package %q: %w", options.Package, err)
		}
	}()

	logf("Extracting files from package %q...", options.Package)

	validOpts, err := getValidOptions(options)
	if err != nil {
		return err
	}

	_, err = os.Stat(validOpts.TargetDir)
	if os.IsNotExist(err) {
		return fmt.Errorf("target directory does not exist")
	} else if err != nil {
		return err
	}

	return extractData(pkgReader, validOpts, DataReader)
}

// ExtractTar is like Extract but for tar archives (e.g. bins) that are not
// wrapped in a .deb ar container.
func ExtractTar(pkgReader io.ReadSeeker, options *ExtractOptions) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("cannot extract from package %q: %w", options.Package, err)
		}
	}()

	logf("Extracting files from package %q...", options.Package)

	validOpts, err := getValidOptions(options)
	if err != nil {
		return err
	}

	_, err = os.Stat(validOpts.TargetDir)
	if os.IsNotExist(err) {
		return fmt.Errorf("target directory does not exist")
	} else if err != nil {
		return err
	}

	return extractData(pkgReader, validOpts, TarReader)
}

// openTarFunc creates a tar stream reader from a seekable package reader.
type openTarFunc func(io.ReadSeeker) (io.ReadCloser, error)

func extractData(pkgReader io.ReadSeeker, options *ExtractOptions, openTar openTarFunc) error {
	dataReader, err := openTar(pkgReader)
	if err != nil {
		return err
	}
	defer dataReader.Close()

	oldUmask := syscall.Umask(0)
	defer func() {
		syscall.Umask(oldUmask)
	}()

	pendingPaths := make(map[string]bool)
	for extractPath, extractInfos := range options.Extract {
		for _, extractInfo := range extractInfos {
			if !extractInfo.Optional {
				pendingPaths[extractPath] = true
				break
			}
		}
	}

	// Store the hard links that we cannot extract when we first iterate over
	// the tarball.
	//
	// This happens because the tarball only stores the contents once in the
	// first entry and the rest of them point to the first one. Therefore, we
	// cannot tell whether we need to extract the content until after we get to
	// a hard link. In this case, we need a second pass.
	pendingHardLinks := make(map[string][]pendingHardLink)

	// When creating a file we will iterate through its parent directories and
	// create them with the permissions defined in the tarball.
	//
	// The assumption is that the tar entries of the parent directories appear
	// before the entry for the file itself. This is the case for .deb files but
	// not for all tarballs.
	tarDirMode := make(map[string]fs.FileMode)
	tarReader := tar.NewReader(dataReader)
	for {
		tarHeader, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		sourcePath, ok := sanitizeTarPath(tarHeader.Name)
		if !ok {
			continue
		}

		sourceIsDir := sourcePath[len(sourcePath)-1] == '/'
		if sourceIsDir {
			tarDirMode[sourcePath] = tarHeader.FileInfo().Mode()
		}

		// Find all globs and copies that require this source, and map them by
		// their target paths on disk.
		targetPaths := map[string][]ExtractInfo{}
		for extractPath, extractInfos := range options.Extract {
			if extractPath == "" {
				continue
			}
			if strings.ContainsAny(extractPath, "*?") {
				if strdist.GlobPath(extractPath, sourcePath) {
					targetPaths[sourcePath] = append(targetPaths[sourcePath], extractInfos...)
					delete(pendingPaths, extractPath)
				}
			} else if extractPath == sourcePath {
				for _, extractInfo := range extractInfos {
					targetPaths[extractInfo.Path] = append(targetPaths[extractInfo.Path], extractInfo)
				}
				delete(pendingPaths, extractPath)
			}
		}
		if len(targetPaths) == 0 {
			// Nothing to do.
			continue
		}

		var contentCache []byte
		contentIsCached := len(targetPaths) > 1 && !sourceIsDir
		if contentIsCached {
			// Read and cache the content so it may be reused.
			// As an alternative, to avoid having an entire file in
			// memory at once this logic might open the first file
			// written and copy it every time. For now, the choice
			// is speed over memory efficiency.
			data, err := io.ReadAll(tarReader)
			if err != nil {
				return err
			}
			contentCache = data
		}

		var pathReader io.Reader = tarReader
		for targetPath, extractInfos := range targetPaths {
			if contentIsCached {
				pathReader = bytes.NewReader(contentCache)
			}
			mode := extractInfos[0].Mode
			for _, extractInfo := range extractInfos {
				if extractInfo.Mode != mode {
					if mode < extractInfo.Mode {
						mode, extractInfo.Mode = extractInfo.Mode, mode
					}
					return fmt.Errorf("path %s requested twice with diverging mode: 0%03o != 0%03o", targetPath, mode, extractInfo.Mode)
				}
			}
			if mode != 0 {
				tarHeader.Mode = int64(mode)
			}
			// Create the parent directories using the permissions from the tarball.
			parents := parentDirs(targetPath)
			for _, path := range parents {
				if path == "/" {
					continue
				}
				mode, ok := tarDirMode[path]
				if !ok {
					continue
				}
				delete(tarDirMode, path)

				createOptions := &fsutil.CreateOptions{
					Root:        options.TargetDir,
					Path:        path,
					Mode:        mode,
					MakeParents: true,
				}
				err := options.Create(nil, createOptions)
				if err != nil {
					return err
				}
			}
			link := tarHeader.Linkname
			if tarHeader.Typeflag == tar.TypeLink {
				// A hard link requires the real path of the target file.
				link = filepath.Join(options.TargetDir, link)
			}

			// Create the entry itself.
			createOptions := &fsutil.CreateOptions{
				Root:         options.TargetDir,
				Path:         targetPath,
				Mode:         tarHeader.FileInfo().Mode(),
				Data:         pathReader,
				Link:         link,
				MakeParents:  true,
				OverrideMode: true,
			}
			err := options.Create(extractInfos, createOptions)
			if err != nil && os.IsNotExist(err) && tarHeader.Typeflag == tar.TypeLink {
				// The hard link could not be created because the content
				// was not extracted previously. Add this hard link entry
				// to the pending list to extract later.
				relLinkPath, ok := sanitizeTarPath(tarHeader.Linkname)
				if !ok {
					return fmt.Errorf("invalid link target %s", tarHeader.Linkname)
				}
				info := pendingHardLink{
					path:         targetPath,
					extractInfos: extractInfos,
				}
				pendingHardLinks[relLinkPath] = append(pendingHardLinks[relLinkPath], info)
			} else if err != nil {
				return err
			}
		}
	}

	if len(pendingHardLinks) > 0 {
		// Go over the tarball again to textract the pending hard links.
		extractHardLinkOptions := &extractHardLinkOptions{
			ExtractOptions: options,
			pendingLinks:   pendingHardLinks,
		}
		_, err := pkgReader.Seek(0, io.SeekStart)
		if err != nil {
			return err
		}
		err = extractHardLinks(pkgReader, extractHardLinkOptions, openTar)
		if err != nil {
			return err
		}
	}

	if len(pendingPaths) > 0 {
		pendingList := make([]string, 0, len(pendingPaths))
		for pendingPath := range pendingPaths {
			pendingList = append(pendingList, pendingPath)
		}
		if len(pendingList) == 1 {
			return fmt.Errorf("no content at %s", pendingList[0])
		} else {
			sort.Strings(pendingList)
			return fmt.Errorf("no content at:\n- %s", strings.Join(pendingList, "\n- "))
		}
	}

	return nil
}

type pendingHardLink struct {
	path         string
	extractInfos []ExtractInfo
}

type extractHardLinkOptions struct {
	*ExtractOptions
	pendingLinks map[string][]pendingHardLink
}

// extractHardLinks iterates through the tarball a second time to extract the
// hard links that were not extracted in the first pass.
func extractHardLinks(pkgReader io.ReadSeeker, opts *extractHardLinkOptions, openTar openTarFunc) error {
	dataReader, err := openTar(pkgReader)
	if err != nil {
		return err
	}
	defer dataReader.Close()

	tarReader := tar.NewReader(dataReader)
	for {
		tarHeader, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		sourcePath, ok := sanitizeTarPath(tarHeader.Name)
		if !ok {
			continue
		}

		links := opts.pendingLinks[sourcePath]
		if len(links) == 0 {
			continue
		}

		// For a target path, the first hard link will be created as a file with
		// the content of the target path. If there are more pending hard links,
		// the remaining ones will be created as hard links with the newly
		// created file as their target.
		absLink := filepath.Join(opts.TargetDir, links[0].path)
		// Extract the content to the first hard link path.
		createOptions := &fsutil.CreateOptions{
			Root: opts.TargetDir,
			Path: links[0].path,
			Mode: tarHeader.FileInfo().Mode(),
			Data: tarReader,
		}
		err = opts.Create(links[0].extractInfos, createOptions)
		if err != nil {
			return err
		}

		// Create the remaining hard links.
		for _, link := range links[1:] {
			createOptions := &fsutil.CreateOptions{
				Root: opts.TargetDir,
				Path: link.path,
				Mode: tarHeader.FileInfo().Mode(),
				// Link to the first file extracted for the hard links.
				Link: absLink,
			}
			err := opts.Create(link.extractInfos, createOptions)
			if err != nil {
				return err
			}
		}
		delete(opts.pendingLinks, sourcePath)
	}

	// If there are pending links, that means the link targets do not come from
	// this package.
	if len(opts.pendingLinks) > 0 {
		var targets []string
		for target := range opts.pendingLinks {
			targets = append(targets, target)
		}
		sort.Strings(targets)
		link := opts.pendingLinks[targets[0]][0]
		return fmt.Errorf("cannot create hard link %s: no content at %s", link.path, targets[0])
	}

	return nil
}

// TarReader takes a Reader for a compressed tar archive (tar.xz) and returns
// a Reader to the decompressed tar stream.
func TarReader(pkgReader io.ReadSeeker) (io.ReadCloser, error) {
	xzReader, err := xz.NewReader(pkgReader)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(xzReader), nil
}

// DataReader takes a Reader for the ar file belonging to a Debian package and
// returns a Reader to the inner tarball.
func DataReader(pkgReader io.ReadSeeker) (io.ReadCloser, error) {
	arReader := ar.NewReader(pkgReader)
	var dataReader io.ReadCloser
	for dataReader == nil {
		arHeader, err := arReader.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("no data payload")
		}
		if err != nil {
			return nil, err
		}
		switch arHeader.Name {
		case "data.tar.gz":
			gzipReader, err := gzip.NewReader(arReader)
			if err != nil {
				return nil, err
			}
			dataReader = gzipReader
		case "data.tar.xz":
			xzReader, err := xz.NewReader(arReader)
			if err != nil {
				return nil, err
			}
			dataReader = io.NopCloser(xzReader)
		case "data.tar.zst":
			zstdReader, err := zstd.NewReader(arReader)
			if err != nil {
				return nil, err
			}
			dataReader = zstdReader.IOReadCloser()
		}
	}

	return dataReader, nil
}

func parentDirs(path string) []string {
	path = filepath.Clean(path)
	parents := make([]string, strings.Count(path, "/"))
	count := 0
	for i, c := range path {
		if c == '/' {
			parents[count] = path[:i+1]
			count++
		}
	}
	return parents
}

// sanitizeTarPath normalizes a source path from a tarball. It handles both
// deb-style paths (prefixed with "./") and plain tar paths (prefixed with "/"
// or without any prefix). Returns the cleaned path starting with "/" and a
// boolean indicating whether the path is valid.
func sanitizeTarPath(path string) (string, bool) {
	if path == "./" || path == "." || path == "/" || path == "" {
		return "", false
	}
	if path[0] == '.' && len(path) > 1 && path[1] == '/' {
		// deb-style: "./usr/bin/ls" -> "/usr/bin/ls"
		return path[1:], true
	}
	if path[0] == '/' {
		// Absolute path: "/usr/bin/ls" -> "/usr/bin/ls"
		return path, true
	}
	// Relative path without prefix: "usr/bin/ls" -> "/usr/bin/ls"
	return "/" + path, true
}
