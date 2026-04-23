package slicer

import (
	"fmt"
	"os"
	"path/filepath"
)

const stateDir = ".chisel"

// MkStateDir ensures the state dir exists under the given directory, with the proper
// permissions.
func MkStateDir(targetDir string, mode os.FileMode) (string, error) {
	var err error
	dir := filepath.Join(targetDir, stateDir)
	defer func() {
		if err != nil {
			err = fmt.Errorf("cannot create state directory: %w", err)
		}
	}()
	err = os.Mkdir(dir, mode)
	if err != nil {
		if !os.IsExist(err) {
			return "", err
		}
		fileinfo, err := os.Lstat(dir)
		if err != nil {
			return "", err
		}
		if !fileinfo.IsDir() {
			return "", fmt.Errorf("existing entry at %s is not a directory", dir)
		}
		// The needed mode might change between Chisel versions. Reset it to ensure
		// backward compatibility.
		err = os.Chmod(dir, mode)
		if err != nil {
			return "", err
		}
	}
	return dir, nil
}
