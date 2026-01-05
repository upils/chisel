package manifestutil

import (
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"github.com/canonical/chisel/public/manifest"
)

type pathInfo struct {
	mode string
	size int64
	link string
	hash string
}

// CheckDir checks the content of the target directory matches with
// the manifest.
// This function works under the assumption the manifest is valid.
// Files not managed by chisel are ignored.
func CheckDir(mfest *manifest.Manifest, rootDir string) error {
	mfestInodeToFSInode := make(map[uint64]uint64)
	err := mfest.IteratePaths("", func(path *manifest.Path) error {
		// Skip manifest files
		if filepath.Base(path.Path) == DefaultFilename {
			return nil
		}
		mfestPathInfo := &pathInfo{
			mode: path.Mode,
			size: int64(path.Size),
			link: path.Link,
			hash: recordedHash(path),
		}

		var link string
		var hash string
		var size int64
		var inode uint64
		fullPath := filepath.Join(rootDir, path.Path)
		info, err := os.Lstat(fullPath)
		if err != nil {
			return err
		}
		mode := info.Mode()
		ftype := mode & fs.ModeType
		switch ftype {
		case fs.ModeDir:
			// Nothing to do
		case fs.ModeSymlink:
			link, err = os.Readlink(fullPath)
			if err != nil {
				return fmt.Errorf("internal error: cannot read symlink %q: %w", fullPath, err)
			}
		case 0: // Regular
			h, err := contentHash(fullPath)
			if err != nil {
				return fmt.Errorf("internal error: cannot compute hash for %q: %w", fullPath, err)
			}
			hash = hex.EncodeToString(h)
			size = info.Size()
		default:
			return fmt.Errorf("inconsistent content: %q has unrecognized type %s", fullPath, mode.String())
		}
		fsEntryInfo := &pathInfo{
			mode: fmt.Sprintf("0%o", unixPerm(mode)),
			size: size,
			link: link,
			hash: hash,
		}
		if !reflect.DeepEqual(mfestPathInfo, fsEntryInfo) {
			return fmt.Errorf("inconsistent content at %q: recorded %+v, observed %+v", path.Path, mfestPathInfo, fsEntryInfo)
		}

		// Check hardlink
		if path.Inode != 0 {
			if ftype != fs.ModeDir {
				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok {
					return fmt.Errorf("internal error: cannot get syscall stat info for %q", info.Name())
				}
				inode = stat.Ino
			}
			recordedInode, ok := mfestInodeToFSInode[path.Inode]
			if !ok {
				mfestInodeToFSInode[path.Inode] = inode
			} else if recordedInode != inode {
				return fmt.Errorf("inconsistent content at %q: file hardlinked to a different inode", path.Path)
			}
		}
		return nil
	})
	return err
}

// recordedHash returns path.FinalSHA256 if present, otherwise path.SHA256.
func recordedHash(path *manifest.Path) string {
	expectedHash := path.FinalSHA256
	if expectedHash == "" {
		expectedHash = path.SHA256
	}
	return expectedHash
}
