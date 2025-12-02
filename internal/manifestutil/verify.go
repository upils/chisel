package manifestutil

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/canonical/chisel/public/manifest"
)

// validateRootfs verify the content of the target directory is in line with
// the manifest.
// This function works under the assumption the manifest was previously
// validated.
// Files not managed by chisel are not checked.
func validateRootfs(m *manifest.Manifest, rootDir string) error {
	pathGroups, err := groupManifestPaths(m)
	if err != nil {
		return err
	}

	for _, group := range pathGroups {
		err := verifyGroup(rootDir, group)
		if err != nil {
			return err
		}
	}

	return nil
}

type pathGroup struct {
	headEntry *manifest.Path
	paths     []string
}

// groupManifestPaths groups paths by inode.
func groupManifestPaths(m *manifest.Manifest) (map[string]*pathGroup, error) {
	pathGroups := make(map[string]*pathGroup)
	inodeGroups := make(map[uint64]string)

	err := m.IteratePaths("", func(path *manifest.Path) error {
		inode := path.Inode
		if inode == 0 {
			// New single path
			pathGroups[path.Path] = &pathGroup{
				headEntry: path,
				paths:     []string{path.Path},
			}
			return nil
		}

		groupKey, ok := inodeGroups[inode]
		if !ok {
			// New group of hardlink
			pathGroups[path.Path] = &pathGroup{
				headEntry: path,
				paths:     []string{path.Path},
			}
			inodeGroups[inode] = path.Path
			return nil
		}
		// Add path to the existing group
		group := pathGroups[groupKey]
		group.paths = append(group.paths, path.Path)

		return nil
	})
	if err != nil {
		return nil, err
	}

	// sort paths
	for _, group := range pathGroups {
		slices.Sort(group.paths)
	}

	return pathGroups, nil
}

// verifyGroup verifies a group of paths
func verifyGroup(rootDir string, group *pathGroup) error {
	path := group.headEntry

	fpath := filepath.Join(rootDir, path.Path)
	info, err := os.Lstat(fpath)
	if err != nil {
		return err
	}

	err = verifyPath(info, fpath, path)
	if err != nil {
		return err
	}

	return verifyHardlinks(info, path.Path, rootDir, group.paths)
}

// verifyPath verifies a single path against its manifest entry
func verifyPath(info os.FileInfo, fpath string, path *manifest.Path) error {
	mode := info.Mode()

	// Verify mode
	if fmt.Sprintf("0%o", unixPerm(mode)) != path.Mode {
		return fmt.Errorf("tampered content: %q mode mismatch: %s recorded, %s observed", path.Path, path.Mode, mode.String())
	}

	// Verify directories
	if strings.HasSuffix(path.Path, "/") {
		if !info.IsDir() {
			return fmt.Errorf("tampered content: %q expected to be a directory", path.Path)
		}
		return nil
	}

	// Verify symlinks
	if len(path.Link) > 0 {
		link, err := os.Readlink(fpath)
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

	// Verify size
	if info.Size() != int64(path.Size) {
		return fmt.Errorf("tampered file: %q, size mimsmatch: %d recorded, %d observed", path.Path, info.Size(), int64(path.Size))
	}

	// Verify hash
	// Most expensive operation, so do it at the end.
	h, err := hash(fpath)
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
}

func verifyHardlinks(headInfo os.FileInfo, headPath string, rootDir string, paths []string) error {
	if len(paths) == 0 {
		// No hardlinks, nothing to do
		return nil
	}

	headInode, err := getPhysicalInode(headInfo)
	if err != nil {
		return err
	}

	for _, siblingPath := range paths {
		if siblingPath == headPath {
			continue
		}
		siblingFullPath := filepath.Join(rootDir, siblingPath)
		sibFi, err := os.Lstat(siblingFullPath)
		if err != nil {
			return err
		}

		sibInode, err := getPhysicalInode(sibFi)
		if err != nil {
			return err
		}

		// Verify Inode Equality
		if sibInode != headInode {
			return fmt.Errorf("tampered content: broken hardlink: %s and %s should share inode but do not", headPath, siblingPath)
		}
	}
	return nil
}

func getPhysicalInode(info os.FileInfo) (uint64, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("cannot get syscall stat info for %q", info.Name())
	}
	return stat.Ino, nil
}
