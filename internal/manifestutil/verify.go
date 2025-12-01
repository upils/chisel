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

	info, err := verifyPath(rootDir, path)
	if err != nil {
		return err
	}

	// Verify hardlinks
	if len(group.paths) == 0 {
		// Not a hardlink, nothing more to do
		return nil
	}

	headInode, err := getPhysicalInode(info)
	if err != nil {
		return err
	}

	return verifyHardlinks(headInode, rootDir, path.Path, group.paths)
}

func verifyPath(rootDir string, path *manifest.Path) (os.FileInfo, error) {
	p := filepath.Join(rootDir, path.Path)
	info, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	mode := info.Mode()
	if fmt.Sprintf("0%o", unixPerm(mode)) != path.Mode {
		return nil, fmt.Errorf("tampered content: %q mode mismatch: %s recorded, %s observed", path.Path, path.Mode, mode.String())
	}

	// Verify directories
	if strings.HasSuffix(path.Path, "/") {
		if !info.IsDir() {
			return nil, fmt.Errorf("tampered content: %q expected to be a directory", path.Path)
		}
		return info, nil
	}

	// Verify symlinks
	if len(path.Link) > 0 {
		link, err := os.Readlink(p)
		if err != nil {
			return nil, err
		}

		if link != path.Link {
			return nil, fmt.Errorf("tampered content: %q link destination mismatch: %s recorded, %s observed", path.Path, path.Link, link)
		}
		return info, nil
	}

	if !mode.IsRegular() {
		return nil, fmt.Errorf("tampered content: unrecognized type of file.")
	}

	// Verify size
	if info.Size() != int64(path.Size) {
		return nil, fmt.Errorf("tampered file: %q, size mimsmatch: %d recorded, %d observed", path.Path, info.Size(), int64(path.Size))
	}

	// Verify hash
	// Most expensive operation, so do it at the end.
	h, err := hash(p)
	if err != nil {
		return nil, err
	}
	hString := hex.EncodeToString(h)
	if len(path.FinalSHA256) > 0 {
		if hString != path.FinalSHA256 {
			return nil, fmt.Errorf("tampered file %q, hash mismatch: %s recorded, %s observed", path.Path, path.FinalSHA256, hString)
		}
	} else if len(path.SHA256) > 0 && hString != path.SHA256 {
		// This is effectively skipping the manifest.wall since no hash is declared on it
		return nil, fmt.Errorf("tampered file %q, sha256 mismatch: %s recorded, %s observed", path.Path, path.SHA256, hString)
	}
	return info, nil
}

func verifyHardlinks(headInode uint64, rootDir string, headPath string, paths []string) error {
	for _, siblingPath := range paths[1:] {
		siblingFullPath := filepath.Join(rootDir, siblingPath)
		sibFi, err := os.Lstat(siblingFullPath)
		if err != nil {
			return err
		}

		// Verify Inode Equality
		sibInode, err := getPhysicalInode(sibFi)
		if err != nil {
			return err
		}

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
