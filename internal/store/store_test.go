package store_test

import (
	"bytes"
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
	tempDir     string
	cacheDir    string
	fakeDoFunc  func(req *http.Request) (*http.Response, error)
	restoreDo   func()
	restoreBulk func()
	envRestore  func()
}

var _ = Suite(&storeSuite{})

func (s *storeSuite) SetUpTest(c *C) {
	s.tempDir = c.MkDir()
	s.cacheDir = filepath.Join(s.tempDir, "cache")
	c.Assert(os.MkdirAll(s.cacheDir, 0o755), IsNil)

	s.envRestore = fakeEnv("")
	s.restoreDo = store.SetHTTPDo(s.doRequest)
	s.restoreBulk = store.SetBulkDo(s.doRequest)
	s.fakeDoFunc = nil
}

func (s *storeSuite) TearDownTest(c *C) {
	s.restoreDo()
	s.restoreBulk()
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

func makeBinInfoBody(name, track, risk, arch, version string, revision int, sha384 string) []byte {
	downloadURL := "https://storage.snapcraftcontent.com/bins/" + name + ".tar.xz"
	return makeBinInfoBodyWithURL(name, track, risk, arch, version, revision, sha384, downloadURL)
}

func makeBinInfoBodyWithURL(name, track, risk, arch, version string, revision int, sha384, downloadURL string) []byte {
	return []byte(fmt.Sprintf(`{
		"name": %q,
		"channel-map": [
			{
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
		]
	}`, name, track+"/"+risk, risk, track, arch, version, revision, downloadURL, sha384))
}

func (s *storeSuite) TestValidateDownloadURL(c *C) {
	tests := []struct {
		url   string
		error string
	}{
		{"https://storage.snapcraftcontent.com/bins/foo.tar.xz", ""},
		{"https://api.snapcraft.io/v2/bins/foo", ""},
		{"https://api.staging.snapcraft.io/v2/bins/foo", ""},
		{"https://sub.storage.snapcraftcontent.com/bins/foo.tar.xz", ""},
		{"https://storage.snapcraftcontent.com:443/bins/foo.tar.xz", ""},
		{"https://Storage.SnapcraftContent.Com/bins/foo.tar.xz", ""},
		{
			"http://storage.snapcraftcontent.com/bins/foo.tar.xz",
			`bin download URL must use HTTPS: "http://storage.snapcraftcontent.com/bins/foo.tar.xz"`,
		},
		{
			"https://evil.example.com/bins/foo.tar.xz",
			`bin download URL has untrusted host "evil.example.com"`,
		},
		{
			"https://Evil.Example.Com/bins/foo.tar.xz",
			`bin download URL has untrusted host "evil.example.com"`,
		},
		{
			"https://storage.snapcraftcontent.com.evil.com/bins/foo.tar.xz",
			`bin download URL has untrusted host "storage.snapcraftcontent.com.evil.com"`,
		},
		{"://invalid-url", `cannot parse bin download URL: .*`},
	}
	for _, test := range tests {
		err := store.ValidateDownloadURL(test.url)
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
	status     int
	statusText string
	body       string
	info       *store.StorePackageInfo
	error      string
}

var infoTests = []infoTest{{
	summary: "Successful info",
	status:  200,
	body:    string(makeBinInfoBody("curl", "latest", "stable", "amd64", "8.5.0", 42, "abc123")),
	info:    &store.StorePackageInfo{Name: "curl", Version: "8.5.0", Revision: 42, SHA384: "abc123"},
}, {
	summary: "Package not found",
	status:  404,
	body:    "not found",
	error:   `bin "curl" not found`,
}, {
	summary: "No release for the requested architecture",
	status:  200,
	body:    string(makeBinInfoBody("curl", "latest", "stable", "arm64", "8.5.0", 42, "abc123")),
	error:   `bin "curl" has no latest/stable release for architecture "amd64"`,
}, {
	summary:    "Server error",
	status:     500,
	statusText: "500 Internal Server Error",
	body:       "boom",
	error:      "cannot fetch from bin store: 500 Internal Server Error",
}, {
	summary: "Malformed response body",
	status:  200,
	body:    "not json",
	error:   "cannot decode bin store response: .*",
}, {
	summary: "Selects the entry matching the requested architecture",
	status:  200,
	body: `{
		"name": "curl",
		"channel-map": [
			{
				"channel": {"name": "latest/stable", "risk": "stable", "track": "latest", "platform": {"architecture": "arm64"}},
				"revision": {"version": "8.0.0", "revision": 1, "download": {"url": "https://storage.snapcraftcontent.com/bins/curl.tar.xz", "sha3-384": "arm64hash", "size": 1024}}
			},
			{
				"channel": {"name": "latest/stable", "risk": "stable", "track": "latest", "platform": {"architecture": "amd64"}},
				"revision": {"version": "8.5.0", "revision": 42, "download": {"url": "https://storage.snapcraftcontent.com/bins/curl.tar.xz", "sha3-384": "amd64hash", "size": 1024}}
			}
		]
	}`,
	info: &store.StorePackageInfo{Name: "curl", Version: "8.5.0", Revision: 42, SHA384: "amd64hash"},
}, {
	summary: "Missing download digest",
	status:  200,
	body:    string(makeBinInfoBody("curl", "latest", "stable", "amd64", "8.5.0", 42, "")),
	error:   `bin "curl" has no download digest`,
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

		info, err := src.Info("curl", "latest", "stable")
		if test.error != "" {
			c.Assert(err, ErrorMatches, test.error)
			continue
		}
		c.Assert(err, IsNil)
		c.Assert(info, DeepEquals, test.info)
	}
}

func (s *storeSuite) TestInfoRequest(c *C) {
	infoBody := makeBinInfoBody("curl", "latest", "stable", "amd64", "8.5.0", 42, "abc123")

	s.fakeDoFunc = func(req *http.Request) (*http.Response, error) {
		c.Assert(req.URL.Path, Equals, "/v2/bins/info/curl")
		c.Assert(req.URL.Query().Get("fields"), Equals, "download,version,revision,channel-map")
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
	infoBody := makeBinInfoBody("curl", "latest", "stable", "amd64", "8.5.0", 42, "abc123")

	s.fakeDoFunc = func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, "/info/curl") {
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader(infoBody)),
			}, nil
		}
		return &http.Response{
			StatusCode: 404,
			Body:       io.NopCloser(strings.NewReader("not found")),
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

	infoBody := makeBinInfoBody("curl", "latest", "stable", "amd64", "8.5.0", 42, digest)

	callCount := 0
	s.fakeDoFunc = func(req *http.Request) (*http.Response, error) {
		callCount++
		if strings.Contains(req.URL.Path, "/info/") {
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

	infoBody := makeBinInfoBody("curl", "latest", "stable", "amd64", "8.5.0", 42, digest)

	infoCallCount := 0
	s.fakeDoFunc = func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, "/info/") {
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
	infoBody := makeBinInfoBodyWithURL("curl", "latest", "stable", "amd64", "8.5.0", 42, "abc123",
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
	c.Assert(err, ErrorMatches, `bin download URL must use HTTPS: "http://evil.example.com/bins/curl.tar.xz"`)
}

func (s *storeSuite) TestFetchMissingDigest(c *C) {
	// The store omits the sha3-384 digest from the response.
	infoBody := makeBinInfoBody("curl", "latest", "stable", "amd64", "8.5.0", 42, "")

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
	c.Assert(err, ErrorMatches, `bin "curl" has no download digest`)
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

	infoBody := makeBinInfoBody("curl", "latest", "stable", "amd64", "8.5.0", 42, "abc123")

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
	infoBody := makeBinInfoBody("curl", "latest", "stable", "amd64", "8.5.0", 42, "abc123")

	s.fakeDoFunc = func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, "/info/") {
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
	c.Assert(err, ErrorMatches, `cannot download bin "curl": 500 Internal Server Error`)
}
