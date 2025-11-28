package manifestutil

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/canonical/chisel/internal/apacheutil"
	"github.com/canonical/chisel/internal/archive"
	"github.com/canonical/chisel/internal/setup"
	"github.com/canonical/chisel/public/jsonwall"
	"github.com/canonical/chisel/public/manifest"
	"github.com/klauspost/compress/zstd"
)

const DefaultFilename = "manifest.wall"

// FindPaths finds the paths marked with "generate:manifest" and
// returns a map from the manifest path to all the slices that declare it.
func FindPaths(slices []*setup.Slice) map[string][]*setup.Slice {
	manifestSlices := make(map[string][]*setup.Slice)
	for _, slice := range slices {
		for path, info := range slice.Contents {
			if info.Generate == setup.GenerateManifest {
				dir := strings.TrimSuffix(path, "**")
				path = filepath.Join(dir, DefaultFilename)
				manifestSlices[path] = append(manifestSlices[path], slice)
			}
		}
	}
	return manifestSlices
}

// FindPathsInRelease finds all the paths marked with "generate:manifest"
// for the given release.
func FindPathsInRelease(r *setup.Release) []string {
	manifests := []string{}
	for _, pkg := range r.Packages {
		for _, slice := range pkg.Slices {
			for path, info := range slice.Contents {
				if info.Generate == setup.GenerateManifest {
					dir := strings.TrimSuffix(path, "**")
					path = filepath.Join(dir, DefaultFilename)
					manifests = append(manifests, path)
				}
			}
		}
	}
	return manifests
}

type WriteOptions struct {
	PackageInfo []*archive.PackageInfo
	Selection   []*setup.Slice
	Report      *Report
}

func Write(options *WriteOptions, writer io.Writer) error {
	dbw := jsonwall.NewDBWriter(&jsonwall.DBWriterOptions{
		Schema: manifest.Schema,
	})

	err := fastValidate(options)
	if err != nil {
		return err
	}

	err = manifestAddPackages(dbw, options.PackageInfo)
	if err != nil {
		return err
	}

	err = manifestAddSlices(dbw, options.Selection)
	if err != nil {
		return err
	}

	err = manifestAddReport(dbw, options.Report)
	if err != nil {
		return err
	}

	_, err = dbw.WriteTo(writer)
	return err
}

func manifestAddPackages(dbw *jsonwall.DBWriter, infos []*archive.PackageInfo) error {
	for _, info := range infos {
		err := dbw.Add(&manifest.Package{
			Kind:    "package",
			Name:    info.Name,
			Version: info.Version,
			Digest:  info.SHA256,
			Arch:    info.Arch,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func manifestAddSlices(dbw *jsonwall.DBWriter, slices []*setup.Slice) error {
	for _, slice := range slices {
		err := dbw.Add(&manifest.Slice{
			Kind: "slice",
			Name: slice.String(),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func manifestAddReport(dbw *jsonwall.DBWriter, report *Report) error {
	for _, entry := range report.Entries {
		sliceNames := []string{}
		for slice := range entry.Slices {
			err := dbw.Add(&manifest.Content{
				Kind:  "content",
				Slice: slice.String(),
				Path:  entry.Path,
			})
			if err != nil {
				return err
			}
			sliceNames = append(sliceNames, slice.String())
		}
		sort.Strings(sliceNames)
		err := dbw.Add(&manifest.Path{
			Kind:        "path",
			Path:        entry.Path,
			Mode:        fmt.Sprintf("0%o", unixPerm(entry.Mode)),
			Slices:      sliceNames,
			SHA256:      entry.SHA256,
			FinalSHA256: entry.FinalSHA256,
			Size:        uint64(entry.Size),
			Link:        entry.Link,
			Inode:       entry.Inode,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func unixPerm(mode fs.FileMode) (perm uint32) {
	perm = uint32(mode.Perm())
	if mode&fs.ModeSticky != 0 {
		perm |= 01000
	}
	return perm
}

// fastValidate validates the data to be written into the manifest.
// This is validating internal structures which are supposed to be correct unless there is
// a bug. As such, only assertions that can be done quickly are performed here, instead
// of it being a comprehensive validation of all the structures.
func fastValidate(options *WriteOptions) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("internal error: invalid manifest: %s", err)
		}
	}()
	pkgExist := map[string]bool{}
	for _, pkg := range options.PackageInfo {
		err := validatePackage(pkg)
		if err != nil {
			return err
		}
		pkgExist[pkg.Name] = true
	}
	sliceExist := map[string]bool{}
	for _, slice := range options.Selection {
		if _, ok := pkgExist[slice.Package]; !ok {
			return fmt.Errorf("slice %s refers to missing package %q", slice.String(), slice.Package)
		}
		sliceExist[slice.String()] = true
	}
	hardLinkGroups := make(map[uint64][]*ReportEntry)
	for _, entry := range options.Report.Entries {
		err := validateReportEntry(&entry)
		if err != nil {
			return err
		}
		for slice := range entry.Slices {
			if _, ok := sliceExist[slice.String()]; !ok {
				return fmt.Errorf("path %q refers to missing slice %s", entry.Path, slice.String())
			}
		}
		if entry.Inode != 0 {
			hardLinkGroups[entry.Inode] = append(hardLinkGroups[entry.Inode], &entry)
		}
	}
	// Entries within a hard link group must have same content.
	for id := 1; id <= len(hardLinkGroups); id++ {
		entries, ok := hardLinkGroups[uint64(id)]
		if !ok {
			return fmt.Errorf("cannot find hard link id %d", id)
		}
		if len(entries) == 1 {
			return fmt.Errorf("hard link group %d has only one path: %s", id, entries[0].Path)
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Path < entries[j].Path
		})
		e0 := entries[0]
		for _, e := range entries[1:] {
			if e.Link != e0.Link || unixPerm(e.Mode) != unixPerm(e0.Mode) || e.SHA256 != e0.SHA256 ||
				e.Size != e0.Size || e.FinalSHA256 != e0.FinalSHA256 {
				return fmt.Errorf("hard linked paths %q and %q have diverging contents", e0.Path, e.Path)
			}
		}
	}

	return nil
}

func validateReportEntry(entry *ReportEntry) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("path %q has invalid options: %s", entry.Path, err)
		}
	}()

	switch entry.Mode & fs.ModeType {
	case 0:
		// Regular file.
	case fs.ModeDir:
		if entry.Link != "" {
			return fmt.Errorf("link set for directory")
		}
		if entry.SHA256 != "" {
			return fmt.Errorf("sha256 set for directory")
		}
		if entry.FinalSHA256 != "" {
			return fmt.Errorf("final_sha256 set for directory")
		}
		if entry.Size != 0 {
			return fmt.Errorf("size set for directory")
		}
	case fs.ModeSymlink:
		if entry.Link == "" {
			return fmt.Errorf("link not set for symlink")
		}
		if entry.SHA256 != "" {
			return fmt.Errorf("sha256 set for symlink")
		}
		if entry.FinalSHA256 != "" {
			return fmt.Errorf("final_sha256 set for symlink")
		}
		if entry.Size != 0 {
			return fmt.Errorf("size set for symlink")
		}
	default:
		return fmt.Errorf("unsupported file type: %s", entry.Path)
	}

	if len(entry.Slices) == 0 {
		return fmt.Errorf("slices is empty")
	}

	return nil
}

func validatePackage(pkg *archive.PackageInfo) (err error) {
	if pkg.Name == "" {
		return fmt.Errorf("package name not set")
	}
	if pkg.Arch == "" {
		return fmt.Errorf("package %q missing arch", pkg.Name)
	}
	if pkg.SHA256 == "" {
		return fmt.Errorf("package %q missing sha256", pkg.Name)
	}
	if pkg.Version == "" {
		return fmt.Errorf("package %q missing version", pkg.Name)
	}
	return nil
}

// Validate checks that the Manifest is valid. Note that to do that it has to
// load practically the whole manifest into memory and unmarshall all the
// entries.
func Validate(mfest *manifest.Manifest) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("invalid manifest: %s", err)
		}
	}()

	pkgExist := map[string]bool{}
	err = mfest.IteratePackages(func(pkg *manifest.Package) error {
		pkgExist[pkg.Name] = true
		return nil
	})
	if err != nil {
		return err
	}

	sliceExist := map[string]bool{}
	err = mfest.IterateSlices("", func(slice *manifest.Slice) error {
		sk, err := apacheutil.ParseSliceKey(slice.Name)
		if err != nil {
			return err
		}
		if !pkgExist[sk.Package] {
			return fmt.Errorf("slice %s refers to missing package %q", slice.Name, sk.Package)
		}
		sliceExist[slice.Name] = true
		return nil
	})
	if err != nil {
		return err
	}

	pathToSlices := map[string][]string{}
	err = mfest.IterateContents("", func(content *manifest.Content) error {
		if !sliceExist[content.Slice] {
			return fmt.Errorf("content path %q refers to missing slice %s", content.Path, content.Slice)
		}
		if !slices.Contains(pathToSlices[content.Path], content.Slice) {
			pathToSlices[content.Path] = append(pathToSlices[content.Path], content.Slice)
		}
		return nil
	})
	if err != nil {
		return err
	}

	done := map[string]bool{}
	err = mfest.IteratePaths("", func(path *manifest.Path) error {
		pathSlices, ok := pathToSlices[path.Path]
		if !ok {
			return fmt.Errorf("path %s has no matching entry in contents", path.Path)
		}
		slices.Sort(pathSlices)
		slices.Sort(path.Slices)
		if !slices.Equal(pathSlices, path.Slices) {
			return fmt.Errorf("path %s and content have diverging slices: %q != %q", path.Path, path.Slices, pathSlices)
		}
		done[path.Path] = true
		return nil
	})
	if err != nil {
		return err
	}

	if len(done) != len(pathToSlices) {
		for path := range pathToSlices {
			return fmt.Errorf("content path %s has no matching entry in paths", path)
		}
	}
	return nil
}

// RootFSManifest extracts the manifest from a targetDir
func RootFSManifest(release *setup.Release, targetDir string) (*manifest.Manifest, error) {
	manifestPaths := FindPathsInRelease(release)
	if len(manifestPaths) == 0 {
		// No manifest in the release means it cannot produce a rootfs that can
		// be recut. Treat this case as cutting a new rootfs.
		return nil, nil
	}

	// Select the first manifest of the list as the reference one for now.
	// Another heuristic could be used (ex. select the one from base-files_chisel).
	refManifestPath := path.Join(targetDir, manifestPaths[0])
	refManifest, err := load(refManifestPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read manifest %q from the root directory: %v", refManifestPath, err)
	}

	err = checkConsistency(refManifestPath, targetDir, manifestPaths[1:])
	if err != nil {
		return nil, err
	}

	rootfsReport, err := reportFromRootfs(targetDir)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Report: %#v\n", rootfsReport)

	manifestReport, err := reportFromManifest(refManifest)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Report from manifest: %#v\n", manifestReport)

	err = validateReportEntries(manifestReport, rootfsReport)
	if err != nil {
		return nil, err
	}

	// err = validateRootfs(refManifest, targetDir)
	// if err != nil {
	// 	return nil, err
	// }
	return refManifest, nil
}

// load reads, validates and returns a manifest.
func load(manifestPath string) (*manifest.Manifest, error) {
	f, err := os.Open(manifestPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r, err := zstd.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	mfest, err := manifest.Read(r)
	if err != nil {
		return nil, err
	}

	err = Validate(mfest)
	if err != nil {
		return nil, err
	}

	return mfest, nil
}

// checkConsistency checks consistency between a list of manifests and a
// reference one.
func checkConsistency(reference string, targetDir string, manifests []string) error {
	hashReference, err := hash(reference)
	if err != nil {
		return err
	}

	infoRef, err := os.Stat(reference)
	if err != nil {
		return err
	}

	modeRef := infoRef.Mode()

	for _, m := range manifests {
		infoManifest, err := os.Stat(path.Join(targetDir, m))
		if err != nil {
			return err
		}

		modeManifest := infoManifest.Mode()
		if modeManifest != modeRef {
			return fmt.Errorf("invalid manifest: permissions on %s (%s) are different from the reference manifest %s (%s)", m, modeManifest, reference, modeRef)
		}

		hashM, err := hash(m)
		if err != nil {
			return err
		}
		if !slices.Equal(hashM, hashReference) {
			return fmt.Errorf("invalid manifest: %s is inconsistent with %s", m, reference)
		}
	}

	return nil
}

func hash(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// SliceKeys returns setup.SliceKeys from a manifest.
func SliceKeys(m *manifest.Manifest) []setup.SliceKey {
	sliceKeys := []setup.SliceKey{}
	m.IterateSlices("", func(slice *manifest.Slice) error {
		sk, err := apacheutil.ParseSliceKey(slice.Name)
		if err != nil {
			return err
		}
		sliceKeys = append(sliceKeys, sk)
		return nil
	})

	return sliceKeys
}

// validateRootfs verify the content of the target directory is in line with
// the manifest.
// This function works under the assumption the manifest was previously
// validated.
func validateRootfs(m *manifest.Manifest, rootDir string) error {
	hardLinkGroups, err := groupHardlinks(m)
	if err != nil {
		return err
	}

	return m.IteratePaths("", func(path *manifest.Path) error {
		p := filepath.Join(rootDir, path.Path)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		mode := info.Mode()
		if fmt.Sprintf("0%o", unixPerm(mode)) != path.Mode {
			return fmt.Errorf("tampered content: %q mode mismatch: %s recorded, %s observed", path.Path, path.Mode, mode.String())
		}

		// Verify directories
		// TODO check sha and final_sha and size
		if strings.HasSuffix(path.Path, "/") {
			if !info.IsDir() {
				return fmt.Errorf("tampered content: %q expected to be a directory", path.Path)
			}
			return nil
		}

		// Verify symlinks
		if len(path.Link) > 0 {
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}

			if link != path.Link {
				return fmt.Errorf("tampered content: %q link destination mismatch: %s recorded, %s observed", path.Path, path.Link, link)
			}
			return nil
		}

		if !mode.IsRegular() {
			return fmt.Errorf("tampered content: unrecognized type of file.")
		}

		// Verify hardlinks
		if path.Inode != 0 {
			paths, ok := hardLinkGroups[path.Inode]
			if !ok {
				return fmt.Errorf("cannot find paths associated to this inode: %d", path.Inode)
			}

			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return fmt.Errorf("cannot get syscall stat info for %q", path.Path)
			}
			nLink := stat.Nlink

			if int(nLink) != len(paths) {
				// Working under the assumption no hardlink not managed by chisel
				// and pointing at a chisel-managed file was added.
				return fmt.Errorf("tampered content: %q hardlinks count mismatch: %d recorded, %d observed", path.Path, len(paths), nLink)
			}
		}

		// Common verification for regular files
		h, err := hash(p)
		if err != nil {
			return err
		}
		hString := hex.EncodeToString(h)
		if len(path.FinalSHA256) > 0 {
			if hString != path.FinalSHA256 {
				return fmt.Errorf("tampered file %q, hash mismatch: %s recorded, %s observed", path.Path, path.FinalSHA256, hString)
			}
		} else if len(path.SHA256) > 0 && hString != path.SHA256 {
			// This is effectively skipping the manifest.wall since no hash is declared on it
			return fmt.Errorf("tampered file %q, sha256 mismatch: %s recorded, %s observed", path.Path, path.SHA256, hString)
		}
		return nil
	})
}

// groupHardlinks groups hardlink paths by inode.
func groupHardlinks(m *manifest.Manifest) (map[uint64][]*manifest.Path, error) {
	hardLinkGroups := make(map[uint64][]*manifest.Path)

	err := m.IteratePaths("", func(path *manifest.Path) error {
		inode := path.Inode
		if inode == 0 {
			return nil
		}
		hardLinkGroups[inode] = append(hardLinkGroups[inode], path)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return hardLinkGroups, nil
}

// reportFromRootfs builds a Report from root directory
func reportFromRootfs(rootDir string) (*Report, error) {
	report, err := NewReport(rootDir)
	if err != nil {
		return nil, fmt.Errorf("internal error: cannot create report: %w", err)
	}

	var inodes []uint64
	pathsByInodes := make(map[uint64][]string)

	dirfs := os.DirFS(report.Root)
	err = fs.WalkDir(dirfs, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk error: %w", err)
		}
		if path == "." {
			return nil
		}
		fpath := filepath.Join(report.Root, path)
		finfo, err := d.Info()
		if err != nil {
			return fmt.Errorf("cannot get stat info for %q: %w", fpath, err)
		}

		entry := ReportEntry{
			Mode: finfo.Mode(),
		}

		var size int

		ftype := finfo.Mode() & fs.ModeType
		switch ftype {
		case fs.ModeDir:
			path = "/" + path + "/"
		case fs.ModeSymlink:
			lpath, err := os.Readlink(fpath)
			if err != nil {
				return err
			}
			path = "/" + path
			entry.Link = lpath
		case 0: // Regular
			data, err := os.ReadFile(fpath)
			if err != nil {
				return fmt.Errorf("cannot read file: %w", err)
			}
			if len(data) >= 0 {
				sum := sha256.Sum256(data)
				entry.SHA256 = hex.EncodeToString(sum[:])
			}
			path = "/" + path
			size = int(finfo.Size())
		default:
			return fmt.Errorf("unknown file type %d: %s", ftype, fpath)
		}
		entry.Path = path
		entry.Size = size

		if ftype != fs.ModeDir {
			stat, ok := finfo.Sys().(*syscall.Stat_t)
			if !ok {
				return fmt.Errorf("cannot get syscall stat info for %q", fpath)
			}
			inode := stat.Ino
			if len(pathsByInodes[inode]) == 1 {
				inodes = append(inodes, inode)
			}
			entry.Inode = inode
			pathsByInodes[inode] = append(pathsByInodes[inode], path)
		}

		report.Entries[path] = entry

		return nil
	})

	return report, nil
}

// reportFromManifest builds a Report from a Manifest
func reportFromManifest(m *manifest.Manifest) (*Report, error) {
	report := &Report{
		Entries: make(map[string]ReportEntry),
	}

	err := m.IteratePaths("", func(path *manifest.Path) error {
		mode, err := strconv.ParseUint(path.Mode, 8, 32)
		if err != nil {
			return fmt.Errorf("cannot parse mode: %v", err)
		}

		entry := ReportEntry{
			Path:        path.Path,
			Mode:        fs.FileMode(mode),
			Size:        int(path.Size),
			FinalSHA256: path.FinalSHA256,
			SHA256:      path.SHA256,
			Inode:       path.Inode,
			Link:        path.Link,
		}
		report.Entries[path.Path] = entry

		return nil
	})

	return report, err
}

// validateReportEntries validates report entries of toValidate against
// entries in the reference. The report under validation can contain more
// entries.
func validateReportEntries(reference, toValidate *Report) error {
	for path, referenceEntry := range reference.Entries {
		var errorMessage string
		entryToValidate, ok := toValidate.Entries[path]
		if !ok {
			return fmt.Errorf("%q is missing", path)
		}

		if entryToValidate.Mode != referenceEntry.Mode {
			errorMessage = fmt.Sprintf("invalid mode: expected %q, found %q", referenceEntry.Mode, entryToValidate.Mode)
		}
		if entryToValidate.Size != referenceEntry.Size {
			errorMessage = fmt.Sprintf("invalid size: expected %d, found %d", referenceEntry.Size, entryToValidate.Size)
		}
		if len(referenceEntry.FinalSHA256) > 0 {
			if entryToValidate.SHA256 != referenceEntry.FinalSHA256 {
				errorMessage = fmt.Sprintf("invalid hash: expected %s, found %s", referenceEntry.FinalSHA256, entryToValidate.SHA256)
			}
		} else if len(referenceEntry.SHA256) > 0 && entryToValidate.SHA256 != referenceEntry.SHA256 {
			errorMessage = fmt.Sprintf("invalid hash: expected %s, found %s", referenceEntry.SHA256, entryToValidate.SHA256)
		}

		if entryToValidate.Link != referenceEntry.Link {
			errorMessage = fmt.Sprintf("invalid link: expected %q, found %q", referenceEntry.Link, entryToValidate.Link)
		}

		if len(errorMessage) > 0 {
			return fmt.Errorf("invalid entry %q: %s", path, errorMessage)
		}
	}

	return nil
}
