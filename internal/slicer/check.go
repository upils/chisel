package slicer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/klauspost/compress/zstd"

	"github.com/canonical/chisel/internal/manifestutil"
	"github.com/canonical/chisel/public/manifest"
)

type pathInfo struct {
	mode string
	size int64
	link string
	hash string
}

func unixPerm(mode fs.FileMode) (perm uint32) {
	perm = uint32(mode.Perm())
	if mode&fs.ModeSticky != 0 {
		perm |= 0o1000
	}
	return perm
}

// checkDir checks the content of the target directory matches with
// the manifest.
// This function works under the assumption the manifest is valid.
// Files not managed by chisel are ignored.
func checkDir(mfest *manifest.Manifest, rootDir string) error {
	singlePathsByFSInode := make(map[uint64]string)
	mfestInodeToFSInode := make(map[uint64]uint64)
	manifestInfos := make(map[string]*pathInfo)
	err := mfest.IteratePaths("", func(path *manifest.Path) error {
		pathHash := path.FinalSHA256
		if pathHash == "" {
			pathHash = path.SHA256
		}
		recordedPathInfo := &pathInfo{
			mode: path.Mode,
			size: int64(path.Size),
			link: path.Link,
			hash: pathHash,
		}

		fsEntryInfo := &pathInfo{}
		fullPath := filepath.Join(rootDir, path.Path)
		info, err := os.Lstat(fullPath)
		if err != nil {
			return err
		}
		mode := info.Mode()
		fsEntryInfo.mode = fmt.Sprintf("0%o", unixPerm(mode))
		ftype := mode & fs.ModeType
		switch ftype {
		case fs.ModeDir:
			// Nothing to do
		case fs.ModeSymlink:
			fsEntryInfo.link, err = os.Readlink(fullPath)
			if err != nil {
				return fmt.Errorf("cannot read symlink %q: %w", fullPath, err)
			}
		case 0: // Regular
			h, err := contentHash(fullPath)
			if err != nil {
				return fmt.Errorf("cannot compute hash for %q: %w", fullPath, err)
			}
			fsEntryInfo.hash = hex.EncodeToString(h)
			fsEntryInfo.size = info.Size()
		default:
			return fmt.Errorf("inconsistent content: %q has unrecognized type %s", fullPath, mode.String())
		}

		// Collect manifests for tailored checking later.
		// Adjust observed hash and size to still compare in a generic way.
		if filepath.Base(path.Path) == manifestutil.DefaultFilename && recordedPathInfo.size == 0 && recordedPathInfo.hash == "" {
			var mfestInfo *pathInfo
			*mfestInfo = *fsEntryInfo
			manifestInfos[path.Path] = mfestInfo
			fsEntryInfo.size = 0
			fsEntryInfo.hash = ""
		}

		if recordedPathInfo.mode != fsEntryInfo.mode {
			return fmt.Errorf("inconsistent mode at %q: recorded %v, observed %v", path.Path, recordedPathInfo.mode, fsEntryInfo.mode)
		}
		if recordedPathInfo.size != fsEntryInfo.size {
			return fmt.Errorf("inconsistent size at %q: recorded %v, observed %v", path.Path, recordedPathInfo.size, fsEntryInfo.size)
		}
		if recordedPathInfo.link != fsEntryInfo.link {
			return fmt.Errorf("inconsistent link at %q: recorded %v, observed %v", path.Path, recordedPathInfo.link, fsEntryInfo.link)
		}
		if recordedPathInfo.hash != fsEntryInfo.hash {
			return fmt.Errorf("inconsistent hash at %q: recorded %v, observed %v", path.Path, recordedPathInfo.hash, fsEntryInfo.hash)
		}

		// Check hardlink
		if ftype != fs.ModeDir {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return fmt.Errorf("cannot get syscall stat info for %q", info.Name())
			}
			inode := stat.Ino

			if path.Inode == 0 {
				// This path must not be linked to any other
				singlePath, ok := singlePathsByFSInode[inode]
				if ok {
					return fmt.Errorf("inconsistent content at %q: file hardlinked to %q", path.Path, singlePath)
				}
				singlePathsByFSInode[inode] = path.Path
			} else {
				recordedInode, ok := mfestInodeToFSInode[path.Inode]
				if !ok {
					mfestInodeToFSInode[path.Inode] = inode
				} else if recordedInode != inode {
					return fmt.Errorf("inconsistent content at %q: file hardlinked to a different inode", path.Path)
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Check manifests
	// They must all be existing, readable and valid manifests.
	// They must be consistent per schema version.
	schemasToManifestInfo := make(map[string]pathInfo)
	for path, info := range manifestInfos {
		fullPath := filepath.Join(rootDir, path)
		f, err := os.Open(fullPath)
		if err != nil {
			return err
		}
		defer f.Close()
		r, err := zstd.NewReader(f)
		if err != nil {
			return err
		}
		defer r.Close()
		mfest, err = manifest.Read(r)
		if err != nil {
			return err
		}
		err = manifestutil.Validate(mfest)
		if err != nil {
			return err
		}
		schema := mfest.Schema()
		refInfo, ok := schemasToManifestInfo[schema]
		if !ok {
			schemasToManifestInfo[schema] = refInfo
			continue
		}

		if refInfo.size != info.size {
			return fmt.Errorf("inconsistent manifest size for version %s at %q: recorded %v, observed %v", schema, path, refInfo.size, info.size)
		}
		if refInfo.hash != info.hash {
			return fmt.Errorf("inconsistent manifest hash for version %s at %q: recorded %v, observed %v", schema, path, refInfo.hash, info.hash)
		}
	}
	return nil
}

func contentHash(path string) ([]byte, error) {
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
