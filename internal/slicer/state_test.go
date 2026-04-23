package slicer_test

import (
	"os"
	"path/filepath"

	. "gopkg.in/check.v1"

	"github.com/canonical/chisel/internal/slicer"
)

type mkStateDirTest struct {
	summary       string
	mode          os.FileMode
	prepareTarget func(c *C, targetDir string)
	dir           string
	error         string
}

var mkStateDirTests = []mkStateDirTest{{
	summary: "Create state dir from scratch",
	mode:    0o755,
	dir:     ".chisel",
}, {
	summary: "Create state dir with different mode",
	mode:    0o700,
	dir:     ".chisel",
}, {
	summary: "Existing state dir gets mode reset",
	mode:    0o755,
	prepareTarget: func(c *C, targetDir string) {
		err := os.Mkdir(filepath.Join(targetDir, ".chisel"), 0o700)
		c.Assert(err, IsNil)
	},
	dir: ".chisel",
}, {
	summary: "Existing non-directory entry at state dir path",
	mode:    0o755,
	prepareTarget: func(c *C, targetDir string) {
		err := os.WriteFile(filepath.Join(targetDir, ".chisel"), []byte("data"), 0o644)
		c.Assert(err, IsNil)
	},
	error: `cannot create state directory: existing entry at .*/\.chisel is not a directory`,
}, {
	summary: "Target dir does not exist",
	mode:    0o755,
	prepareTarget: func(c *C, targetDir string) {
		err := os.RemoveAll(targetDir)
		c.Assert(err, IsNil)
	},
	error: `cannot create state directory: mkdir .*/\.chisel: no such file or directory`,
}}

func (s *S) TestMkStateDir(c *C) {
	for _, test := range mkStateDirTests {
		c.Logf("Summary: %s", test.summary)

		targetDir := c.MkDir()
		if test.prepareTarget != nil {
			test.prepareTarget(c, targetDir)
		}

		dir, err := slicer.MkStateDir(targetDir, test.mode)
		if test.error != "" {
			c.Assert(err, ErrorMatches, test.error)
			continue
		}

		c.Assert(err, IsNil)
		c.Assert(dir, Equals, filepath.Join(targetDir, test.dir))

		info, err := os.Lstat(dir)
		c.Assert(err, IsNil)
		c.Assert(info.IsDir(), Equals, true)
		c.Assert(info.Mode().Perm(), Equals, test.mode)
	}
}
