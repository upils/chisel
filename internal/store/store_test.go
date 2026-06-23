package store_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/sha3"
	. "gopkg.in/check.v1"

	"github.com/canonical/chisel/internal/cache"
	"github.com/canonical/chisel/internal/store"
)

type storeSuite struct {
	tempDir    string
	cacheDir   string
	fakeDoFunc func(req *http.Request) (*http.Response, error)
	restore    func()
	envRestore func()
}

var _ = Suite(&storeSuite{})

func (s *storeSuite) SetUpTest(c *C) {
	s.tempDir = c.MkDir()
	s.cacheDir = filepath.Join(s.tempDir, "cache")
	c.Assert(os.MkdirAll(s.cacheDir, 0o755), IsNil)

	s.envRestore = fakeEnv("")
	s.restore = store.FakeDo(s.doRequest)
	s.fakeDoFunc = nil
}

func (s *storeSuite) TearDownTest(c *C) {
	s.restore()
	s.envRestore()
}

func (s *storeSuite) doRequest(req *http.Request) (*http.Response, error) {
	if s.fakeDoFunc != nil {
		return s.fakeDoFunc(req)
	}
	return nil, fmt.Errorf("unexpected HTTP request: %s", req.URL.String())
}

func fakeEnv(staging string) func() {
	oldStaging := os.Getenv(store.BinStagingEnvVar)
	if staging != "" {
		os.Setenv(store.BinStagingEnvVar, staging)
	} else {
		os.Unsetenv(store.BinStagingEnvVar)
	}
	return func() {
		if oldStaging != "" {
			os.Setenv(store.BinStagingEnvVar, oldStaging)
		} else {
			os.Unsetenv(store.BinStagingEnvVar)
		}
	}
}

func sha384Hash(data []byte) string {
	h := sha3.New384()
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func makeResolveBody(name, track, risk, arch, version string, revision int, sha384 string) []byte {
	downloadURL := "https://api.snapcraft.io/api/v1/bins/download/" + name + ".bin"
	return makeResolveBodyWithURL(name, track, risk, arch, version, revision, sha384, downloadURL)
}

func makeResolveBodyWithURL(name, track, risk, arch, version string, revision int, sha384, downloadURL string) []byte {
	return []byte(fmt.Sprintf(`{
		"craft-results": [],
		"package-results": [
			{
				"instance-key": %q,
				"status": "ok",
				"result": {
					"channel": {
						"name": %q,
						"risk": %q,
						"track": %q,
						"platform": {"architecture": %q}
					},
					"revision": {
						"version": %q,
						"revision": %d,
						"download": {
							"url": %q,
							"sha3-384": %q,
							"size": 1024
						}
					}
				}
			}
		]
	}`, name, track+"/"+risk, risk, track, arch, version, revision, downloadURL, sha384))
}

func makeResolveErrorBody(name, code, message string) []byte {
	return []byte(fmt.Sprintf(`{
		"craft-results": [],
		"package-results": [
			{
				"instance-key": %q,
				"status": "error",
				"error": {"code": %q, "message": %q},
				"result": null
			}
		]
	}`, name, code, message))
}

func (s *storeSuite) TestValidateDownloadURL(c *C) {
	tests := []struct {
		url         string
		allowedHost string
		error       string
	}{
		{"https://api.snapcraft.io/api/v1/bins/download/foo.bin", "api.snapcraft.io", ""},
		// Staging host is rejected when the production host is allowed.
		{
			"https://api.staging.snapcraft.io/api/v1/bins/download/foo.bin",
			"api.snapcraft.io",
			`download URL has untrusted host "api.staging.snapcraft.io"`,
		},
		// Staging host is allowed when it is the allowed host.
		{"https://api.staging.snapcraft.io/api/v1/bins/download/foo.bin", "api.staging.snapcraft.io", ""},
		// Production API host is rejected when the staging host is allowed.
		{
			"https://api.snapcraft.io/api/v1/bins/download/foo.bin",
			"api.staging.snapcraft.io",
			`download URL has untrusted host "api.snapcraft.io"`,
		},
		{
			"http://api.snapcraft.io/api/v1/bins/download/foo.bin",
			"api.snapcraft.io",
			`download URL must use HTTPS: "http://api.snapcraft.io/api/v1/bins/download/foo.bin"`,
		},
		{
			"https://evil.example.com/api/v1/bins/download/foo.bin",
			"api.snapcraft.io",
			`download URL has untrusted host "evil.example.com"`,
		},
		{
			"https://Evil.Example.Com/api/v1/bins/download/foo.bin",
			"api.snapcraft.io",
			`download URL has untrusted host "evil.example.com"`,
		},
		{
			"https://api.snapcraft.io.evil.com/api/v1/bins/download/foo.bin",
			"api.snapcraft.io",
			`download URL has untrusted host "api.snapcraft.io.evil.com"`,
		},
		{"://invalid-url", "api.snapcraft.io", `cannot parse download URL: .*`},
	}
	for _, test := range tests {
		err := store.ValidateDownloadURL(test.url, test.allowedHost)
		if test.error == "" {
			c.Assert(err, IsNil)
		} else {
			c.Assert(err, ErrorMatches, test.error)
		}
	}
}

func (s *storeSuite) TestOpenArchValidation(c *C) {
	tests := []struct {
		arch  string
		error string
	}{
		{"amd64", ""},
		{"arm64", ""},
		{"invalid", "invalid package architecture: invalid"},
	}
	for _, test := range tests {
		_, err := store.Open(&store.Options{
			Arch:     test.arch,
			CacheDir: s.cacheDir,
			Kind:     "bin",
		})
		if test.error == "" {
			c.Assert(err, IsNil)
		} else {
			c.Assert(err, ErrorMatches, test.error)
		}
	}
}

type infoTest struct {
	summary    string
	risk       string
	status     int
	statusText string
	body       string
	info       *store.StorePackageInfo
	error      string
}

var infoTests = []infoTest{{
	summary: "Successful info",
	risk:    "stable",
	status:  200,
	body:    string(makeResolveBody("curl", "latest", "stable", "amd64", "8.5.0", 42, "abc123")),
	info:    &store.StorePackageInfo{Name: "curl", Version: "8.5.0", Revision: 42, SHA384: "abc123"},
}, {
	summary: "Defaults to stable risk when unspecified",
	risk:    "",
	status:  200,
	body:    string(makeResolveBody("curl", "latest", "stable", "amd64", "8.5.0", 42, "abc123")),
	info:    &store.StorePackageInfo{Name: "curl", Version: "8.5.0", Revision: 42, SHA384: "abc123"},
}, {
	summary: "Package not found",
	risk:    "stable",
	status:  200,
	body:    string(makeResolveErrorBody("curl", "package-not-found", "Package not found")),
	error:   `package "curl" not found: Package not found`,
}, {
	summary:    "Server error",
	risk:       "stable",
	status:     500,
	statusText: "500 Internal Server Error",
	body:       "boom",
	error:      "cannot fetch from store: 500 Internal Server Error",
}, {
	summary: "Malformed response body",
	risk:    "stable",
	status:  200,
	body:    "not json",
	error:   "cannot decode store response: .*",
}, {
	summary: "Missing download digest",
	risk:    "stable",
	status:  200,
	body:    string(makeResolveBody("curl", "latest", "stable", "amd64", "8.5.0", 42, "")),
	error:   `package "curl" has no download digest`,
}}

func (s *storeSuite) TestInfo(c *C) {
	for _, test := range infoTests {
		c.Logf("Summary: %s", test.summary)

		s.fakeDoFunc = func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: test.status,
				Status:     test.statusText,
				Body:       io.NopCloser(strings.NewReader(test.body)),
			}, nil
		}

		src, err := store.Open(&store.Options{
			Arch:     "amd64",
			CacheDir: s.cacheDir,
			Kind:     "bin",
		})
		c.Assert(err, IsNil)

		info, err := src.Info("curl", "latest", test.risk)
		if test.error != "" {
			c.Assert(err, ErrorMatches, test.error)
			continue
		}
		c.Assert(err, IsNil)
		c.Assert(info, DeepEquals, test.info)
	}
}

func (s *storeSuite) TestInfoRequest(c *C) {
	infoBody := makeResolveBody("curl", "latest", "stable", "amd64", "8.5.0", 42, "abc123")

	s.fakeDoFunc = func(req *http.Request) (*http.Response, error) {
		c.Assert(req.Method, Equals, "POST")
		c.Assert(req.URL.Path, Equals, "/v2/revisions/resolve")
		c.Assert(req.Header.Get("Content-Type"), Equals, "application/json")
		c.Assert(req.Header.Get("Accept"), Equals, "application/json")

		var body map[string]any
		err := json.NewDecoder(req.Body).Decode(&body)
		c.Assert(err, IsNil)
		pkgs := body["packages"].([]any)
		c.Assert(pkgs, HasLen, 1)
		pkg := pkgs[0].(map[string]any)
		c.Assert(pkg["instance-key"], Equals, "curl")
		c.Assert(pkg["namespace"], Equals, "bin")
		c.Assert(pkg["name"], Equals, "curl")
		c.Assert(pkg["channel"], Equals, "latest/stable")
		c.Assert(pkg["platform"].(map[string]any)["architecture"], Equals, "amd64")

		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(infoBody)),
		}, nil
	}

	src, err := store.Open(&store.Options{
		Arch:     "amd64",
		CacheDir: s.cacheDir,
		Kind:     "bin",
	})
	c.Assert(err, IsNil)

	_, err = src.Info("curl", "latest", "stable")
	c.Assert(err, IsNil)
}

func (s *storeSuite) TestExists(c *C) {
	okBody := makeResolveBody("curl", "latest", "stable", "amd64", "8.5.0", 42, "abc123")
	notFoundBody := makeResolveErrorBody("nonexistent", "package-not-found", "Package not found")

	s.fakeDoFunc = func(req *http.Request) (*http.Response, error) {
		var body struct {
			Packages []struct {
				Name string `json:"name"`
			} `json:"packages"`
		}
		err := json.NewDecoder(req.Body).Decode(&body)
		c.Assert(err, IsNil)
		pkgName := ""
		if len(body.Packages) > 0 {
			pkgName = body.Packages[0].Name
		}
		if pkgName == "curl" {
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader(okBody)),
			}, nil
		}
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(notFoundBody)),
		}, nil
	}

	src, err := store.Open(&store.Options{
		Arch:     "amd64",
		CacheDir: s.cacheDir,
		Kind:     "bin",
	})
	c.Assert(err, IsNil)

	c.Assert(src.Exists("curl", "latest", "stable"), Equals, true)
	c.Assert(src.Exists("nonexistent", "latest", "stable"), Equals, false)
}

func (s *storeSuite) TestFetchCacheMiss(c *C) {
	tarData := []byte("fake tar.xz content")
	digest := sha384Hash(tarData)

	infoBody := makeResolveBody("curl", "latest", "stable", "amd64", "8.5.0", 42, digest)

	callCount := 0
	s.fakeDoFunc = func(req *http.Request) (*http.Response, error) {
		callCount++
		if req.URL.Path == "/v2/revisions/resolve" {
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader(infoBody)),
			}, nil
		}
		// Download URL
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(tarData)),
		}, nil
	}

	src, err := store.Open(&store.Options{
		Arch:     "amd64",
		CacheDir: s.cacheDir,
		Kind:     "bin",
	})
	c.Assert(err, IsNil)

	reader, info, err := src.Fetch("curl", "latest", "stable")
	c.Assert(err, IsNil)
	defer reader.Close()

	c.Assert(info.Name, Equals, "curl")
	c.Assert(info.Version, Equals, "8.5.0")
	c.Assert(info.SHA384, Equals, digest)

	data, err := io.ReadAll(reader)
	c.Assert(err, IsNil)
	c.Assert(data, DeepEquals, tarData)
	c.Assert(callCount, Equals, 2)

	// Verify it's in the cache.
	cc := cache.Cache{Dir: s.cacheDir}
	cached, err := cc.Read(cache.SHA384, digest)
	c.Assert(err, IsNil)
	c.Assert(cached, DeepEquals, tarData)
}

func (s *storeSuite) TestFetchCacheHit(c *C) {
	tarData := []byte("fake tar.xz content")
	digest := sha384Hash(tarData)

	// Pre-populate the cache.
	cc := cache.Cache{Dir: s.cacheDir}
	err := cc.Write(cache.SHA384, digest, tarData)
	c.Assert(err, IsNil)

	infoBody := makeResolveBody("curl", "latest", "stable", "amd64", "8.5.0", 42, digest)

	infoCallCount := 0
	s.fakeDoFunc = func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/v2/revisions/resolve" {
			infoCallCount++
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader(infoBody)),
			}, nil
		}
		return nil, fmt.Errorf("download should not be called for cache hit")
	}

	src, err := store.Open(&store.Options{
		Arch:     "amd64",
		CacheDir: s.cacheDir,
		Kind:     "bin",
	})
	c.Assert(err, IsNil)

	reader, info, err := src.Fetch("curl", "latest", "stable")
	c.Assert(err, IsNil)
	defer reader.Close()

	c.Assert(info.Name, Equals, "curl")
	c.Assert(info.SHA384, Equals, digest)
	c.Assert(infoCallCount, Equals, 1)

	data, err := io.ReadAll(reader)
	c.Assert(err, IsNil)
	c.Assert(data, DeepEquals, tarData)
}

func (s *storeSuite) TestFetchInvalidDownloadURL(c *C) {
	// Override the download URL to an invalid one.
	infoBody := makeResolveBodyWithURL("curl", "latest", "stable", "amd64", "8.5.0", 42, "abc123",
		"http://evil.example.com/bins/curl.tar.xz")

	s.fakeDoFunc = func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(infoBody)),
		}, nil
	}

	src, err := store.Open(&store.Options{
		Arch:     "amd64",
		CacheDir: s.cacheDir,
		Kind:     "bin",
	})
	c.Assert(err, IsNil)

	_, _, err = src.Fetch("curl", "latest", "stable")
	c.Assert(err, ErrorMatches, `download URL must use HTTPS: "http://evil.example.com/bins/curl.tar.xz"`)
}

func (s *storeSuite) TestFetchMissingDigest(c *C) {
	// The store omits the sha3-384 digest from the response.
	infoBody := makeResolveBody("curl", "latest", "stable", "amd64", "8.5.0", 42, "")

	s.fakeDoFunc = func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(infoBody)),
		}, nil
	}

	src, err := store.Open(&store.Options{
		Arch:     "amd64",
		CacheDir: s.cacheDir,
		Kind:     "bin",
	})
	c.Assert(err, IsNil)

	_, _, err = src.Fetch("curl", "latest", "stable")
	c.Assert(err, ErrorMatches, `package "curl" has no download digest`)
}

func (s *storeSuite) TestStagingEnvVar(c *C) {
	s.envRestore()
	s.envRestore = fakeEnv("1")

	src, err := store.Open(&store.Options{
		Arch:     "amd64",
		CacheDir: s.cacheDir,
		Kind:     "bin",
	})
	c.Assert(err, IsNil)

	infoBody := makeResolveBody("curl", "latest", "stable", "amd64", "8.5.0", 42, "abc123")

	s.fakeDoFunc = func(req *http.Request) (*http.Response, error) {
		// Verify staging URL is used.
		c.Assert(req.URL.Host, Equals, "api.staging.snapcraft.io")
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(infoBody)),
		}, nil
	}

	_, err = src.Info("curl", "latest", "stable")
	c.Assert(err, IsNil)
}

func (s *storeSuite) TestOpenUnsupportedKind(c *C) {
	_, err := store.Open(&store.Options{
		Arch:     "amd64",
		CacheDir: s.cacheDir,
		Kind:     "snap",
	})
	c.Assert(err, ErrorMatches, `unsupported store kind "snap"`)
}

func (s *storeSuite) TestFetchDownloadError(c *C) {
	infoBody := makeResolveBody("curl", "latest", "stable", "amd64", "8.5.0", 42, "abc123")

	s.fakeDoFunc = func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/v2/revisions/resolve" {
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader(infoBody)),
			}, nil
		}
		return &http.Response{
			StatusCode: 500,
			Status:     "500 Internal Server Error",
			Body:       io.NopCloser(strings.NewReader("boom")),
		}, nil
	}

	src, err := store.Open(&store.Options{
		Arch:     "amd64",
		CacheDir: s.cacheDir,
		Kind:     "bin",
	})
	c.Assert(err, IsNil)

	_, _, err = src.Fetch("curl", "latest", "stable")
	c.Assert(err, ErrorMatches, `cannot download package "curl": 500 Internal Server Error`)
}
