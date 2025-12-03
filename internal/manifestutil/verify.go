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

// VerifyDir verifies the content of the target directory matches with
// the manifest.
// This function works under the assumption the manifest is valid.
// Files not managed by chisel are ignored.
func VerifyDir(mfest *manifest.Manifest, rootDir string) error {
	pathGroups, err := groupPaths(mfest)
	if err != nil {
		return err
	}

	for _, group := range pathGroups {
		err = verifyGroup(group, rootDir)
		if err != nil {
			return err
		}
	}

	return nil
}

type pathGroup struct {
	head  *manifest.Path
	paths []string
}

// groupPaths groups paths by inode.
// Returns a slice of path groups where each group represents either:
// - A standalone file (inode 0)
// - A set of hardlinked files (same non-zero inode)
func groupPaths(mfest *manifest.Manifest) ([]*pathGroup, error) {
	pathGroups := []*pathGroup{}
	inodeToGroup := make(map[uint64]*pathGroup)

	err := mfest.IteratePaths("", func(path *manifest.Path) error {
		inode := path.Inode
		if inode == 0 {
			// Standalone path
			pathGroups = append(pathGroups, &pathGroup{
				head:  path,
				paths: []string{path.Path},
			})
			return nil
		}

		// Hardlinked path
		group, ok := inodeToGroup[inode]
		if !ok {
			// New group of hardlinks
			group = &pathGroup{
				head:  path,
				paths: []string{path.Path},
			}
			inodeToGroup[inode] = group
			pathGroups = append(pathGroups, group)
			return nil
		}
		// Add path to the existing group
		group.paths = append(group.paths, path.Path)

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Sort paths in groups for deterministic behavior
	for _, group := range pathGroups {
		if len(group.paths) > 1 {
			slices.Sort(group.paths)
		}
	}

	return pathGroups, nil
}

// verifyGroup verifies a group of paths
func verifyGroup(group *pathGroup, rootDir string) error {
	path := group.head
	fpath := filepath.Join(rootDir, path.Path)
	info, err := os.Lstat(fpath)
	if err != nil {
		return err
	}

	if err := verifyPath(path, info, fpath); err != nil {
		return err
	}

	return verifyHardlinks(info, path.Path, rootDir, group.paths)
}

// verifyPath verifies a single path against its manifest entry
func verifyPath(path *manifest.Path, info os.FileInfo, fpath string) error {
	mode := info.Mode()

	if err := verifyFileType(path, info); err != nil {
		return err
	}

	if err := verifyMode(path, mode); err != nil {
		return err
	}

	if pathIsDir(path.Path) {
		// Directories have no additional checks
		return nil
	}

	if len(path.Link) > 0 {
		return verifySymlink(path, fpath)
	}

	if !mode.IsRegular() {
		return fmt.Errorf("tampered content: %q has unrecognized type %s", path.Path, mode.String())
	}

	if err := verifySize(path, info); err != nil {
		return err
	}

	// Verify hash
	// Most expensive operation, so do it at the end.
	return verifyHash(path, fpath)
}

// verifyFileType checks that the file type matches expectations.
func verifyFileType(path *manifest.Path, info os.FileInfo) error {
	mode := info.Mode()
	isDir := pathIsDir(path.Path)
	isSymlink := path.Link != ""

	if isDir && !info.IsDir() {
		return fmt.Errorf("tampered content: %q expected to be a directory but found %s",
			path.Path, mode.Type().String())
	}

	if !isDir && info.IsDir() {
		return fmt.Errorf("tampered content: %q is a directory but manifest expects a file",
			path.Path)
	}

	if isSymlink && mode.Type() != os.ModeSymlink {
		return fmt.Errorf("tampered content: %q expected to be a symlink but found %s",
			path.Path, mode.Type().String())
	}

	if !isSymlink && mode.Type() == os.ModeSymlink {
		return fmt.Errorf("tampered content: %q is a symlink but manifest expects regular file",
			path.Path)
	}

	return nil
}

// verifyMode checks file permissions match the manifest.
func verifyMode(path *manifest.Path, mode os.FileMode) error {
	expectedMode := path.Mode
	actualMode := fmt.Sprintf("0%o", unixPerm(mode))

	if actualMode != expectedMode {
		return fmt.Errorf("tampered content: %q mode mismatch: expected %s, observed %s",
			path.Path, expectedMode, actualMode)
	}

	return nil
}

// verifySymlink checks symlink target matches the manifest.
func verifySymlink(path *manifest.Path, fpath string) error {
	link, err := os.Readlink(fpath)
	if err != nil {
		return fmt.Errorf("cannot read symlink %q: %w", path.Path, err)
	}

	if link != path.Link {
		return fmt.Errorf("tampered content: %q symlink mismatch: expected %q → %q, observed %q → %q",
			path.Path, path.Path, path.Link, path.Path, link)
	}

	return nil
}

// verifySize checks file size matches the manifest.
func verifySize(path *manifest.Path, info os.FileInfo) error {
	expected := int64(path.Size)
	actual := info.Size()

	if actual != expected {
		return fmt.Errorf("tampered file: %q size mismatch: expected %d bytes, observed %d bytes",
			path.Path, expected, actual)
	}

	return nil
}

// verifyHash verifies file content hash.
// Uses FinalSHA256 if present, otherwise SHA256.
// Files without any hash declaration are skipped (e.g., manifest.wall).
func verifyHash(path *manifest.Path, fpath string) error {
	expectedHash := path.FinalSHA256
	hashType := "final"

	if expectedHash == "" {
		expectedHash = path.SHA256
		hashType = "original"
	}

	// Skip hash verification if no hash is declared
	if expectedHash == "" {
		// This is skipping manifest.wall that is generated
		// during the cut operation and have no predetermined hash
		return nil
	}

	h, err := hash(fpath)
	if err != nil {
		return fmt.Errorf("internal error: cannot compute hash for %q: %w", path.Path, err)
	}

	actualHash := hex.EncodeToString(h)
	if actualHash != expectedHash {
		return fmt.Errorf("tampered file: %q %s hash mismatch: expected %s, observed %s",
			path.Path, hashType, expectedHash, actualHash)
	}

	return nil
}

// verifyHardlinks verifies that all paths in the list share the same inode.
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

// getPhysicalInode retrieves the inode number from os.FileInfo
func getPhysicalInode(info os.FileInfo) (uint64, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("internal error: cannot get syscall stat info for %q", info.Name())
	}
	return stat.Ino, nil
}

func pathIsDir(path string) bool {
	return strings.HasSuffix(path, "/")
}
