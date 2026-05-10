package deb_test

import (
	"bytes"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	. "gopkg.in/check.v1"

	"github.com/canonical/chisel/internal/deb"
	"github.com/canonical/chisel/internal/fsutil"
	"github.com/canonical/chisel/internal/testutil"
)

type extractTest struct {
	summary string
	pkgdata []byte
	options deb.ExtractOptions
	hackopt func(c *C, o *deb.ExtractOptions)
	result  map[string]string
	// paths which the extractor did not create explicitly.
	notCreated []string
	error      string
}

var extractTests = []extractTest{{
	summary: "Extract nothing",
	pkgdata: testutil.PackageData["test-package"],
	options: deb.ExtractOptions{
		Extract: nil,
	},
	result: map[string]string{},
}, {
	summary: "Extract a few entries",
	pkgdata: testutil.PackageData["test-package"],
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/dir/file": {{
				Path: "/dir/file",
			}},
			"/dir/other-file": {{
				Path: "/dir/other-file",
			}},
			"/dir/several/levels/deep/file": {{
				Path: "/dir/several/levels/deep/file",
			}},
			"/dir/nested/": {{
				Path: "/dir/nested/",
			}},
			"/other-dir/": {{
				Path: "/other-dir/",
			}},
		},
	},
	result: map[string]string{
		"/dir/":                         "dir 0755",
		"/dir/file":                     "file 0644 cc55e2ec",
		"/dir/nested/":                  "dir 0755",
		"/dir/other-file":               "file 0644 63d5dd49",
		"/dir/several/":                 "dir 0755",
		"/dir/several/levels/":          "dir 0755",
		"/dir/several/levels/deep/":     "dir 0755",
		"/dir/several/levels/deep/file": "file 0644 6bc26dff",
		"/other-dir/":                   "dir 0755",
	},
	notCreated: []string{},
}, {
	summary: "Extract a few entries, nil Create closure",
	pkgdata: testutil.PackageData["test-package"],
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/dir/file": {{
				Path: "/dir/file",
			}},
			"/dir/other-file": {{
				Path: "/dir/other-file",
			}},
			"/dir/several/levels/deep/file": {{
				Path: "/dir/several/levels/deep/file",
			}},
			"/dir/nested/": {{
				Path: "/dir/nested/",
			}},
			"/other-dir/": {{
				Path: "/other-dir/",
			}},
		},
	},
	result: map[string]string{
		"/dir/":                         "dir 0755",
		"/dir/file":                     "file 0644 cc55e2ec",
		"/dir/nested/":                  "dir 0755",
		"/dir/other-file":               "file 0644 63d5dd49",
		"/dir/several/":                 "dir 0755",
		"/dir/several/levels/":          "dir 0755",
		"/dir/several/levels/deep/":     "dir 0755",
		"/dir/several/levels/deep/file": "file 0644 6bc26dff",
		"/other-dir/":                   "dir 0755",
	},
	hackopt: func(c *C, o *deb.ExtractOptions) {
		o.Create = nil
	},
}, {
	summary: "Copy a couple of entries elsewhere",
	pkgdata: testutil.PackageData["test-package"],
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/dir/file": {{
				Path: "/foo/file-copy",
				Mode: 0o600,
			}},
			"/dir/several/levels/deep/": {{
				Path: "/foo/bar/dir-copy",
				Mode: 0o700,
			}},
		},
	},
	result: map[string]string{
		"/foo/":              "dir 0755",
		"/foo/bar/":          "dir 0755",
		"/foo/bar/dir-copy/": "dir 0700",
		"/foo/file-copy":     "file 0600 cc55e2ec",
	},
	notCreated: []string{"/foo/", "/foo/bar/"},
}, {
	summary: "Copy same file twice",
	pkgdata: testutil.PackageData["test-package"],
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/dir/file": {{
				Path: "/dir/foo/file-copy-1",
			}, {
				Path: "/dir/bar/file-copy-2",
			}},
		},
	},
	result: map[string]string{
		"/dir/":                "dir 0755",
		"/dir/bar/":            "dir 0755",
		"/dir/bar/file-copy-2": "file 0644 cc55e2ec",
		"/dir/foo/":            "dir 0755",
		"/dir/foo/file-copy-1": "file 0644 cc55e2ec",
	},
	notCreated: []string{"/dir/bar/", "/dir/foo/"},
}, {
	summary: "Globbing a single dir level",
	pkgdata: testutil.PackageData["test-package"],
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/dir/s*/": {{
				Path: "/dir/s*/",
			}},
		},
	},
	result: map[string]string{
		"/dir/":         "dir 0755",
		"/dir/several/": "dir 0755",
	},
	notCreated: []string{},
}, {
	summary: "Globbing for files with multiple levels at once",
	pkgdata: testutil.PackageData["test-package"],
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/dir/s**": {{
				Path: "/dir/s**",
			}},
		},
	},
	result: map[string]string{
		"/dir/":                         "dir 0755",
		"/dir/several/":                 "dir 0755",
		"/dir/several/levels/":          "dir 0755",
		"/dir/several/levels/deep/":     "dir 0755",
		"/dir/several/levels/deep/file": "file 0644 6bc26dff",
	},
	notCreated: []string{},
}, {
	summary: "Globbing multiple paths",
	pkgdata: testutil.PackageData["test-package"],
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/dir/s**": {{
				Path: "/dir/s**",
			}},
			"/dir/n*/": {{
				Path: "/dir/n*/",
			}},
		},
	},
	result: map[string]string{
		"/dir/":                         "dir 0755",
		"/dir/nested/":                  "dir 0755",
		"/dir/several/":                 "dir 0755",
		"/dir/several/levels/":          "dir 0755",
		"/dir/several/levels/deep/":     "dir 0755",
		"/dir/several/levels/deep/file": "file 0644 6bc26dff",
	},
	notCreated: []string{},
}, {
	summary: "Globbing must have matching source and target",
	pkgdata: testutil.PackageData["test-package"],
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/foo/b**": {{
				Path: "/foo/g**",
			}},
		},
	},
	error: `cannot extract from package "test-package": when using wildcards source and target paths must match: /foo/b\*\*`,
}, {
	summary: "Globbing must also have a single target",
	pkgdata: testutil.PackageData["test-package"],
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/foo/b**": {{
				Path: "/foo/b**",
			}, {
				Path: "/foo/g**",
			}},
		},
	},
	error: `cannot extract from package "test-package": when using wildcards source and target paths must match: /foo/b\*\*`,
}, {
	summary: "Globbing cannot change modes",
	pkgdata: testutil.PackageData["test-package"],
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/dir/n**": {{
				Path: "/dir/n**",
				Mode: 0o777,
			}},
		},
	},
	error: `cannot extract from package "test-package": when using wildcards source and target paths must match: /dir/n\*\*`,
}, {
	summary: "Missing file",
	pkgdata: testutil.PackageData["test-package"],
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/missing-file": {{
				Path: "/missing-file",
			}},
		},
	},
	error: `cannot extract from package "test-package": no content at /missing-file`,
}, {
	summary: "Missing directory",
	pkgdata: testutil.PackageData["test-package"],
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/missing-dir/": {{
				Path: "/missing-dir/",
			}},
		},
	},
	error: `cannot extract from package "test-package": no content at /missing-dir/`,
}, {
	summary: "Missing glob",
	pkgdata: testutil.PackageData["test-package"],
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/missing-dir/**": {{
				Path: "/missing-dir/**",
			}},
		},
	},
	error: `cannot extract from package "test-package": no content at /missing-dir/\*\*`,
}, {
	summary: "Missing multiple entries",
	pkgdata: testutil.PackageData["test-package"],
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/missing-file": {{
				Path: "missing-file",
			}},
			"/missing-dir/": {{
				Path: "/missing-dir/",
			}},
		},
	},
	error: `cannot extract from package "test-package": no content at:\n- /missing-dir/\n- /missing-file`,
}, {
	summary: "Optional entries may be missing",
	pkgdata: testutil.PackageData["test-package"],
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/dir/": {{
				Path: "/dir/",
			}},
			"/dir/optional": {{
				Path:     "/other-dir/foo",
				Optional: true,
			}},
			"/optional-dir/": {{
				Path:     "/foo/optional-dir/",
				Optional: true,
			}},
		},
	},
	result: map[string]string{
		"/dir/": "dir 0755",
	},
	notCreated: []string{},
}, {
	summary: "Optional entries mixed in cannot be missing",
	pkgdata: testutil.PackageData["test-package"],
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/dir/missing-file": {{
				Path:     "/dir/optional",
				Optional: true,
			}, {
				Path:     "/dir/not-optional",
				Optional: false,
			}},
		},
	},
	error: `cannot extract from package "test-package": no content at /dir/missing-file`,
}, {
	summary: "Extract non-ASCII path and preserve parent directories permissions",
	pkgdata: testutil.MustMakeDeb([]testutil.TarEntry{
		testutil.Dir(0o755, "./"),
		testutil.Dir(0o766, "./日本/"),
		testutil.Reg(0o644, "./日本/語", "whatever"),
	}),
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/日本/語": {{
				Path: "/日本/語",
			}},
		},
	},
	result: map[string]string{
		"/日本/":  "dir 0766",
		"/日本/語": "file 0644 85738f8f",
	},
	notCreated: []string{},
}, {
	summary: "Entries for same destination must have the same mode",
	pkgdata: testutil.PackageData["test-package"],
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/dir/": {{
				Path: "/dir/",
				Mode: 0o777,
			}},
			"/d**": {{
				Path: "/d**",
			}},
		},
	},
	error: `cannot extract from package "test-package": path /dir/ requested twice with diverging mode: 0777 != 0000`,
}, {
	summary: "Single hard link entry can be extracted with the content entry",
	pkgdata: testutil.MustMakeDeb([]testutil.TarEntry{
		testutil.Dir(0o755, "./"),
		testutil.Reg(0o644, "./file", "text for file"),
		testutil.Hrd(0o644, "./hardlink", "./file"),
	}),
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/**": {{
				Path: "/**",
			}},
		},
	},
	result: map[string]string{
		"/file":     "file 0644 28121945 <1>",
		"/hardlink": "file 0644 28121945 <1>",
	},
	notCreated: []string{},
}, {
	summary: "Single hard link entry can be extracted without the content entry",
	pkgdata: testutil.MustMakeDeb([]testutil.TarEntry{
		testutil.Dir(0o755, "./"),
		testutil.Reg(0o644, "./file", "text for file"),
		testutil.Hrd(0o644, "./hardlink", "./file"),
	}),
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/hardlink": {{
				Path: "/hardlink",
			}},
		},
	},
	result: map[string]string{
		"/hardlink": "file 0644 28121945",
	},
	notCreated: []string{},
}, {
	summary: "Dangling hard link",
	pkgdata: testutil.MustMakeDeb([]testutil.TarEntry{
		testutil.Dir(0o755, "./"),
		testutil.Hrd(0o644, "./hardlink", "./non-existing-target"),
	}),
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/hardlink": {{
				Path: "/hardlink",
			}},
		},
	},
	error: `cannot extract from package "test-package": cannot create hard link /hardlink: no content at /non-existing-target`,
}, {
	summary: "Multiple dangling hard links",
	pkgdata: testutil.MustMakeDeb([]testutil.TarEntry{
		testutil.Dir(0o755, "./"),
		testutil.Hrd(0o644, "./hardlink1", "./non-existing-target"),
		testutil.Hrd(0o644, "./hardlink2", "./non-existing-target"),
	}),
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/**": {{
				Path: "/**",
			}},
		},
	},
	error: `cannot extract from package "test-package": cannot create hard link /hardlink1: no content at /non-existing-target`,
}, {
	summary: "Hard link does not follow the symlink",
	pkgdata: testutil.MustMakeDeb([]testutil.TarEntry{
		testutil.Dir(0o755, "./"),
		testutil.Lnk(0o644, "./symlink", "./file"),
		testutil.Hrd(0o644, "./hardlink", "./symlink"),
	}),
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/**": {{
				Path: "/**",
			}},
		},
	},
	result: map[string]string{
		"/hardlink": "symlink ./file <1>",
		"/symlink":  "symlink ./file <1>",
	},
	notCreated: []string{},
}, {
	summary: "Explicit extraction overrides existing file",
	pkgdata: testutil.PackageData["test-package"],
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/dir/": {{
				Path: "/dir/",
				Mode: 0o777,
			}},
		},
	},
	hackopt: func(c *C, o *deb.ExtractOptions) {
		err := os.Mkdir(path.Join(o.TargetDir, "/dir"), 0o666)
		c.Assert(err, IsNil)
	},
	result: map[string]string{
		"/dir/": "dir 0777",
	},
	notCreated: []string{},
}, {
	summary: "Hardlink cannot escape target directory",
	pkgdata: testutil.MustMakeDeb([]testutil.TarEntry{
		testutil.Dir(0o755, "./"),
		testutil.Hrd(0o644, "./hardlink", "/etc/group"),
	}),
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/**": {{
				Path: "/**",
			}},
		},
	},
	error: `cannot extract from package "test-package": cannot create hard link /hardlink: no content at /etc/group`,
}, {
	summary: "Cannot extract outside of target directory",
	pkgdata: testutil.MustMakeDeb([]testutil.TarEntry{
		testutil.Dir(0o755, "./"),
		testutil.Reg(0o644, "./../file", "hijacking system file"),
	}),
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/**": {{
				Path: "/**",
			}},
		},
	},
	error: `cannot extract from package "test-package": cannot create path /[a-z0-9\-\/]*/file outside of root /[a-z0-9\-\/]*`,
}}

func (s *S) TestExtract(c *C) {
	for _, test := range extractTests {
		c.Logf("Test: %s", test.summary)
		dir := c.MkDir()
		options := test.options
		options.Package = "test-package"
		options.TargetDir = dir
		createdPaths := make(map[string]bool)
		options.Create = func(_ []deb.ExtractInfo, o *fsutil.CreateOptions) error {
			relPath := filepath.Clean("/" + strings.TrimPrefix(o.Path, dir))
			if o.Mode.IsDir() {
				relPath = relPath + "/"
			}
			createdPaths[relPath] = true
			_, err := fsutil.Create(o)
			return err
		}

		if test.hackopt != nil {
			test.hackopt(c, &options)
		}

		err := deb.Extract(bytes.NewReader(test.pkgdata), &options)
		if test.error != "" {
			c.Assert(err, ErrorMatches, test.error)
			continue
		} else {
			c.Assert(err, IsNil)
		}

		if test.notCreated != nil {
			notCreated := []string{}
			for path := range test.result {
				if !createdPaths[path] {
					notCreated = append(notCreated, path)
				}
			}
			sort.Strings(notCreated)
			sort.Strings(test.notCreated)
			c.Assert(notCreated, DeepEquals, test.notCreated)
		}

		result := testutil.TreeDump(dir)
		c.Assert(result, DeepEquals, test.result)
	}
}

var extractCreateCallbackTests = []struct {
	summary string
	pkgdata []byte
	options deb.ExtractOptions
	calls   map[string][]deb.ExtractInfo
}{{
	summary: "Create is called with the set of ExtractInfo(s) that match the file",
	pkgdata: testutil.MustMakeDeb([]testutil.TarEntry{
		testutil.Dir(0o755, "./"),
		testutil.Dir(0o766, "./dir/"),
		testutil.Reg(0o644, "./dir/file", "whatever"),
	}),
	options: deb.ExtractOptions{
		Extract: map[string][]deb.ExtractInfo{
			"/dir/": {{
				Path: "/dir/",
			}},
			"/d**": {{
				Path: "/d**",
			}},
			"/d?r/": {{
				Path: "/d?r/",
			}},
			"/dir/file": {{
				Path: "/dir/file",
			}, {
				Path: "/dir/file-cpy",
			}},
			"/foo/": {{
				Path:     "/foo/",
				Optional: true,
			}},
		},
	},
	calls: map[string][]deb.ExtractInfo{
		"/dir/": {
			{
				Path: "/d**",
			},
			{
				Path: "/d?r/",
			},
			{
				Path: "/dir/",
			},
		},
		"/dir/file": {
			{
				Path: "/d**",
			},
			{
				Path: "/dir/file",
			},
		},
		"/dir/file-cpy": {
			{
				Path: "/dir/file-cpy",
			},
		},
	},
}}

func (s *S) TestExtractCreateCallback(c *C) {
	for _, test := range extractCreateCallbackTests {
		c.Logf("Test: %s", test.summary)
		dir := c.MkDir()
		options := test.options
		options.Package = "test-package"
		options.TargetDir = dir
		createExtractInfos := map[string][]deb.ExtractInfo{}
		options.Create = func(extractInfos []deb.ExtractInfo, o *fsutil.CreateOptions) error {
			if extractInfos == nil {
				// Creating implicit parent directories, we don't care about those.
				return nil
			}
			relPath := filepath.Clean("/" + strings.TrimPrefix(o.Path, dir))
			if o.Mode.IsDir() {
				relPath = relPath + "/"
			}
			sort.Slice(extractInfos, func(i, j int) bool {
				return extractInfos[i].Path < extractInfos[j].Path
			})
			createExtractInfos[relPath] = extractInfos
			return nil
		}

		err := deb.Extract(bytes.NewReader(test.pkgdata), &options)
		c.Assert(err, IsNil)

		c.Assert(createExtractInfos, DeepEquals, test.calls)
	}
}
