package manifestutil

import (
	"encoding/hex"
	"errors"
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

	var allErrors []error
	for _, group := range pathGroups {
		err := verifyGroup(rootDir, group)
		if err != nil {
			allErrors = append(allErrors, err)
		}
	}

	return errors.Join(allErrors...)
}

type pathGroup struct {
	headEntry *manifest.Path
	paths     []string
}

// groupManifestPaths groups paths by inode.
// Returns a slice of path groups where each group represents either:
// - A standalone file (inode 0)
// - A set of hardlinked files (same non-zero inode)
func groupManifestPaths(m *manifest.Manifest) ([]*pathGroup, error) {
	pathGroups := []*pathGroup{}
	inodeToGroup := make(map[uint64]*pathGroup)

	err := m.IteratePaths("", func(path *manifest.Path) error {
		inode := path.Inode
		if inode == 0 {
			// Standalone path
			pathGroups = append(pathGroups, &pathGroup{
				headEntry: path,
				paths:     []string{path.Path},
			})
			return nil
		}

		// Hardlinked path
		group, ok := inodeToGroup[inode]
		if !ok {
			// New group of hardlinks
			group = &pathGroup{
				headEntry: path,
				paths:     []string{path.Path},
			}
			inodeToGroup[inode] = group
			pathGroups = append(pathGroups, group)
			return nil
		} else {
			// Add path to the existing group
			group.paths = append(group.paths, path.Path)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// sort paths
	for _, group := range pathGroups {
		if len(group.paths) > 1 {
			slices.Sort(group.paths)
		}
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

	var allErrors []error
	if err := verifyPath(info, fpath, path); err != nil {
		allErrors = append(allErrors, err)
	}

	if err := verifyHardlinks(info, path.Path, rootDir, group.paths); err != nil {
		allErrors = append(allErrors, err)
	}

	return errors.Join(allErrors...)
}

// verifyPath verifies a single path against its manifest entry
func verifyPath(info os.FileInfo, fpath string, path *manifest.Path) error {
	mode := info.Mode()

	if err := verifyFileType(info, path); err != nil {
		return err
	}

	if err := verifyMode(mode, path); err != nil {
		return err
	}

	if strings.HasSuffix(path.Path, "/") {
		// Directories have no additional checks
		return nil
	}

	if len(path.Link) > 0 {
		return verifySymlink(fpath, path)
	}

	if !mode.IsRegular() {
		return fmt.Errorf("tampered content: %q has unrecognized type %s.", path.Path, mode.String())
	}

	if err := verifySize(info, path); err != nil {
		return err
	}

	// Verify hash
	// Most expensive operation, so do it at the end.
	return verifyHash(fpath, path)
}

// verifyFileType checks that the file type matches expectations.
func verifyFileType(info os.FileInfo, path *manifest.Path) error {
	mode := info.Mode()
	isDir := strings.HasSuffix(path.Path, "/")
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
func verifyMode(mode os.FileMode, path *manifest.Path) error {
	if path.Mode == "" {
		return fmt.Errorf("internal error: missing mode for path %q", path.Path)
	}

	expectedMode := path.Mode
	actualMode := fmt.Sprintf("0%o", unixPerm(mode))

	if actualMode != expectedMode {
		return fmt.Errorf("tampered content: %q mode mismatch: expected %s, observed %s",
			path.Path, expectedMode, actualMode)
	}

	return nil
}

// verifySymlink checks symlink target matches the manifest.
func verifySymlink(fpath string, path *manifest.Path) error {
	if path.Link == "" {
		return fmt.Errorf("internal error: path %q marked as symlink but no target specified", path.Path)
	}

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
func verifySize(info os.FileInfo, path *manifest.Path) error {
	expected := int64(path.Size)
	actual := info.Size()

	if actual != expected {
		return fmt.Errorf("tampered file: %q size mismatch: expected %d bytes, observed %d bytes",
			path.Path, expected, actual)
	}

	return nil
}

// verifyHash verifies file content hash.
// Uses FinalSHA256 if present (post-mutation hash), otherwise SHA256 (original file hash).
// Files without any hash declaration are skipped (e.g., manifest.wall).
func verifyHash(fpath string, path *manifest.Path) error {
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

	if len(expectedHash) != 64 {
		return fmt.Errorf("internal error: invalid SHA256 hash length for %q: %d",
			path.Path, len(expectedHash))
	}

	h, err := hash(fpath)
	if err != nil {
		return fmt.Errorf("cannot compute hash for %q: %w", path.Path, err)
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
		return 0, fmt.Errorf("cannot get syscall stat info for %q", info.Name())
	}
	return stat.Ino, nil
}
