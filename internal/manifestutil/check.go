package manifestutil

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
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
func CheckDir(mfest *manifest.Manifest, mfestPath string, rootDir string) error {
	mfestFullPath := filepath.Join(rootDir, mfestPath)
	h, err := contentHash(mfestFullPath)
	if err != nil {
		return fmt.Errorf("cannot compute hash for %q: %w", mfestFullPath, err)
	}
	mfestHash := hex.EncodeToString(h)
	mfestInfo, err := os.Lstat(mfestFullPath)
	if err != nil {
		return err
	}
	mfestSize := mfestInfo.Size()

	singlePathsByFSInode := make(map[uint64]string)
	mfestInodeToFSInode := make(map[uint64]uint64)
	err = mfest.IteratePaths("", func(path *manifest.Path) error {
		pathHash := path.FinalSHA256
		if pathHash == "" {
			pathHash = path.SHA256
		}
		size := int64(path.Size)
		if filepath.Base(path.Path) == DefaultFilename {
			// Recorded hash and size are empty for a manifest path,
			// so set the hash and size of the reference as the "recorded" values.
			pathHash = mfestHash
			size = mfestSize
		}
		recordedPathInfo := &pathInfo{
			mode: path.Mode,
			size: size,
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

		if recordedPathInfo.mode != fsEntryInfo.mode {
			return fmt.Errorf("inconsistent mode at %q: recorded %+v, observed %+v", path.Path, recordedPathInfo.mode, fsEntryInfo.mode)
		}
		if recordedPathInfo.size != fsEntryInfo.size {
			return fmt.Errorf("inconsistent size at %q: recorded %+v, observed %+v", path.Path, recordedPathInfo.size, fsEntryInfo.size)
		}
		if recordedPathInfo.link != fsEntryInfo.link {
			return fmt.Errorf("inconsistent link at %q: recorded %+v, observed %+v", path.Path, recordedPathInfo.link, fsEntryInfo.link)
		}
		if recordedPathInfo.hash != fsEntryInfo.hash {
			return fmt.Errorf("inconsistent hash at %q: recorded %+v, observed %+v", path.Path, recordedPathInfo.hash, fsEntryInfo.hash)
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
	return err
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
