package slicer

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/canonical/chisel/internal/manifestutil"
	"github.com/canonical/chisel/internal/setup"
	"github.com/canonical/chisel/public/manifest"
)

// merge applies the content from the workDir to the targetDir. This
// process assumes the targetDir was verified with prevManifest, and so
// prevManifest is an accurate representation of files and directories
// previously cut by Chisel in the targetDir.
func merge(targetDir string, workDir string, prevManifest *manifest.Manifest, release *setup.Release) error {
	logf("Merging cut in %s...", targetDir)
	newManifest, err := SelectValidManifest(workDir, release)
	if err != nil {
		return fmt.Errorf("internal error: cannot select manifest from working directory: %s", err)
	}

	// Step 1: Identify new and missing entries.
	entries := make(map[string]*manifest.Path)
	err = newManifest.IteratePaths("", func(path *manifest.Path) error {
		entries[path.Path] = path
		return nil
	})
	if err != nil {
		return err
	}
	missingPaths := make([]string, 0, len(entries))
	newEntries := maps.Clone(entries)
	err = prevManifest.IteratePaths("", func(path *manifest.Path) error {
		_, ok := entries[path.Path]
		if ok {
			delete(newEntries, path.Path)
		} else {
			missingPaths = append(missingPaths, path.Path)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Step 2: Verify no new path will collide with user content.
	// Existing directories are accepted.
	newPaths := slices.Sorted(maps.Keys(newEntries))
	for _, path := range newPaths {
		absPath := filepath.Clean(filepath.Join(targetDir, path))
		fileInfo, err := os.Lstat(absPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if !fileInfo.IsDir() {
			return fmt.Errorf("cannot override user content: %s exists", path)
		}
	}

	// Step 3: Remove content removed from packages/slices.
	// An entry listed in the previous manifest but missing from the new one
	// means it is not part of the package/slice anymore, so remove it.
	// Doing the removing before updating content prevents from collisions in the
	// next step if a path changed type in the package (ex. a dir became a file).
	// This works because we can differentiate files and directories in
	// the manifest due to the trailing slash on directories.
	// These files/directories are safe to remove because the TargetDir
	// verification ensured they were unmodified.
	slices.Sort(missingPaths)
	slices.Reverse(missingPaths)
	// Go through the list in reverse order to empty directories before removing
	// them. Any ENOTEMPTY error encountered means user content is in the directory
	// and Chisel does not manage it anymore.
	for _, path := range missingPaths {
		absPath := filepath.Clean(filepath.Join(targetDir, path))
		err = os.Remove(absPath)
		if err != nil && !os.IsNotExist(err) {
			if errors.Is(err, syscall.ENOTEMPTY) {
				logf("Keep %s as not empty after package content removal", path)
				continue
			}
			return err
		}
	}

	// Step 4: Apply WorkDir content to TargetDir.
	paths := slices.Sorted(maps.Keys(entries))
	for _, path := range paths {
		var prevEntry *manifest.Path
		err := prevManifest.IteratePaths(path, func(prevPath *manifest.Path) error {
			if path == prevPath.Path {
				prevEntry = prevPath
			}
			return nil
		})
		if err != nil {
			return err
		}
		entry := entries[path]
		if prevEntry != nil {
			// Skip the entry if both previous and new one are identical, except for
			// manifests. No Size/SHA256/FinalSH2A56 are recorded for manifests, so make
			// sure they are NOT skipped.
			if prevEntry.Mode == entry.Mode &&
				prevEntry.Size == entry.Size &&
				prevEntry.Link == entry.Link &&
				prevEntry.SHA256 == entry.SHA256 &&
				prevEntry.FinalSHA256 == entry.FinalSHA256 &&
				(prevEntry.Inode != 0) == (entry.Inode != 0) &&
				// Do not skip manifests.
				(filepath.Base(prevEntry.Path) != manifestutil.DefaultFilename &&
					prevEntry.Size == 0 &&
					prevEntry.SHA256 == "") {
				// The entry did not change, nothing to do.
				continue
			}
		}
		// When extracting the content, a great care is taken to create parent
		// directories respecting the tarball permissions. However this approach
		// can create implicit parents, not recorded in the manifest. Make sure
		// to replicate these directories in the TargetDir to sustain the same
		// guarantees as a normal cut.
		// Even if unlikely, this operation can fail if a user file has the
		// same path as one of the implicit parent directory replicated here.
		if err := replicateParentDirs(workDir, targetDir, path); err != nil {
			return fmt.Errorf("cannot create parent directory for %q: %s", path, err)
		}
		// The removal done at step 3 ensures that if the destination path exists
		// it is of the same type (dir or file/symlink) as the source. So any error
		// here is considered a failure because it can only mean one of these things:
		// - An OS error happened, we cannot do anything about it;
		// - There is a collision with a directory containing user content and not
		// removed at step 3. This content must not be deleted;
		// - Content was modified in the rootfs between its verification and this
		//   step. This process does not try to solve this case.
		srcPath := filepath.Clean(filepath.Join(workDir, path))
		dstPath := filepath.Clean(filepath.Join(targetDir, path))
		if strings.HasSuffix(path, "/") {
			permissions, err := strconv.ParseUint(entry.Mode, 8, 32)
			if err != nil {
				return fmt.Errorf("cannot parse mode %q: %w", entry.Mode, err)
			}
			mode := fs.FileMode(permissions)
			mkdirErr := os.Mkdir(dstPath, mode)
			if mkdirErr != nil {
				if os.IsExist(mkdirErr) {
					err = os.Chmod(dstPath, mode)
				} else {
					err = mkdirErr
				}
				if err != nil {
					return err
				}
			}
		} else {
			err = os.Rename(srcPath, dstPath)
			if err != nil {
				return fmt.Errorf("cannot move file at %q: %s", path, err)
			}
		}
	}
	return nil
}

// replicateParentDirs replicates the parent directories of targetPath in dstRoot.
// Fails if any non-directory is on the way.
func replicateParentDirs(srcRoot string, dstRoot string, targetPath string) error {
	parents := parentDirs(targetPath)
	for _, path := range parents {
		if path == "/" {
			continue
		}
		srcPath := filepath.Clean(filepath.Join(srcRoot, path))
		srcInfo, err := os.Stat(srcPath)
		if err != nil {
			return err
		}
		dstPath := filepath.Clean(filepath.Join(dstRoot, path))
		err = os.Mkdir(dstPath, srcInfo.Mode())
		if err != nil {
			if !os.IsExist(err) {
				return err
			}
			fileinfo, err := os.Lstat(dstPath)
			if err != nil {
				return err
			}
			if !fileinfo.IsDir() {
				return fmt.Errorf("cannot create directory, found a non-directory at %s", dstPath)
			}
			return os.Chmod(dstPath, srcInfo.Mode())
		}
	}
	return nil
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
