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
	"github.com/canonical/chisel/internal/testutil"
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
	oldStaging := os.Getenv(store.StagingEnvVar)
	if staging != "" {
		os.Setenv(store.StagingEnvVar, staging)
	} else {
		os.Unsetenv(store.StagingEnvVar)
	}
	return func() {
		if oldStaging != "" {
			os.Setenv(store.StagingEnvVar, oldStaging)
		} else {
			os.Unsetenv(store.StagingEnvVar)
		}
	}
}

func sha384Hash(data []byte) string {
	h := sha3.New384()
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func makeBinInfoResponse(name, track, risk, arch, version string, revision int, sha384 string) *binInfoResponseJSON {
	return &binInfoResponseJSON{
		Name: name,
		ChannelMap: []binChannelMapJSON{
			{
				Channel: binChannelJSON{
					Name:  track + "/" + risk,
					Risk:  risk,
					Track: track,
					Platform: binPlatformJSON{
						Architecture: arch,
					},
				},
				Revision: binRevisionJSON{
					Version:  version,
					Revision: revision,
					Download: binDownloadJSON{
						URL:    "https://storage.snapcraftcontent.com/bins/" + name + ".tar.xz",
						SHA384: sha384,
						Size:   1024,
					},
				},
			},
		},
	}
}

// JSON structures matching the internal binInfoResponse for test construction.
type binInfoResponseJSON struct {
	Name       string              `json:"name"`
	ChannelMap []binChannelMapJSON `json:"channel-map"`
}

type binChannelMapJSON struct {
	Channel  binChannelJSON  `json:"channel"`
	Revision binRevisionJSON `json:"revision"`
}

type binChannelJSON struct {
	Name     string          `json:"name"`
	Risk     string          `json:"risk"`
	Track    string          `json:"track"`
	Platform binPlatformJSON `json:"platform"`
}

type binPlatformJSON struct {
	Architecture string `json:"architecture"`
}

type binRevisionJSON struct {
	Version  string          `json:"version"`
	Revision int             `json:"revision"`
	Download binDownloadJSON `json:"download"`
}

type binDownloadJSON struct {
	URL    string `json:"url"`
	SHA384 string `json:"sha3-384"`
	Size   int64  `json:"size"`
}

func (s *storeSuite) TestValidateDownloadURL(c *C) {
	tests := []struct {
		url    string
		errStr string
	}{
		{"https://storage.snapcraftcontent.com/bins/foo.tar.xz", ""},
		{"https://api.snapcraft.io/v2/bins/foo", ""},
		{"https://api.staging.snapcraft.io/v2/bins/foo", ""},
		{"https://sub.storage.snapcraftcontent.com/bins/foo.tar.xz", ""},
		{"http://storage.snapcraftcontent.com/bins/foo.tar.xz", "must use HTTPS"},
		{"https://evil.example.com/bins/foo.tar.xz", "untrusted host"},
		{"https://storage.snapcraftcontent.com.evil.com/bins/foo.tar.xz", "untrusted host"},
		{"://invalid-url", "cannot parse"},
	}
	for _, test := range tests {
		err := store.ValidateDownloadURL(test.url)
		if test.errStr == "" {
			c.Assert(err, IsNil)
		} else {
			c.Assert(err, NotNil)
			c.Assert(err.Error(), testutil.Contains, test.errStr)
		}
	}
}

func (s *storeSuite) TestOpenArchValidation(c *C) {
	tests := []struct {
		arch   string
		errStr string
	}{
		{"amd64", ""},
		{"arm64", ""},
		{"invalid", "invalid package architecture"},
	}
	for _, test := range tests {
		_, err := store.Open(&store.Options{
			Arch:     test.arch,
			CacheDir: s.cacheDir,
		})
		if test.errStr == "" {
			c.Assert(err, IsNil)
		} else {
			c.Assert(err, NotNil)
			c.Assert(err.Error(), testutil.Contains, test.errStr)
		}
	}
}

func (s *storeSuite) TestInfoSuccess(c *C) {
	infoResp := makeBinInfoResponse("curl", "latest", "stable", "amd64", "8.5.0", 42, "abc123")
	infoBody, _ := json.Marshal(infoResp)

	s.fakeDoFunc = func(req *http.Request) (*http.Response, error) {
		c.Assert(req.URL.Path, Equals, "/v2/bins/info/curl")
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(infoBody)),
		}, nil
	}

	src, err := store.Open(&store.Options{
		Arch:     "amd64",
		CacheDir: s.cacheDir,
	})
	c.Assert(err, IsNil)

	info, err := src.Info("curl", "latest", "stable")
	c.Assert(err, IsNil)
	c.Assert(info.Name, Equals, "curl")
	c.Assert(info.Version, Equals, "8.5.0")
	c.Assert(info.Revision, Equals, 42)
	c.Assert(info.SHA384, Equals, "abc123")
}

func (s *storeSuite) TestInfoNotFound(c *C) {
	s.fakeDoFunc = func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 404,
			Body:       io.NopCloser(strings.NewReader("not found")),
		}, nil
	}

	src, err := store.Open(&store.Options{
		Arch:     "amd64",
		CacheDir: s.cacheDir,
	})
	c.Assert(err, IsNil)

	_, err = src.Info("nonexistent", "latest", "stable")
	c.Assert(err, NotNil)
	c.Assert(err.Error(), testutil.Contains, "not found")
}

func (s *storeSuite) TestInfoNoMatchingChannel(c *C) {
	infoResp := makeBinInfoResponse("curl", "latest", "stable", "arm64", "8.5.0", 42, "abc123")
	infoBody, _ := json.Marshal(infoResp)

	s.fakeDoFunc = func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(infoBody)),
		}, nil
	}

	src, err := store.Open(&store.Options{
		Arch:     "amd64",
		CacheDir: s.cacheDir,
	})
	c.Assert(err, IsNil)

	// The response only has arm64, but we're asking for amd64.
	_, err = src.Info("curl", "latest", "stable")
	c.Assert(err, NotNil)
	c.Assert(err.Error(), testutil.Contains, "has no")
}

func (s *storeSuite) TestExists(c *C) {
	infoResp := makeBinInfoResponse("curl", "latest", "stable", "amd64", "8.5.0", 42, "abc123")
	infoBody, _ := json.Marshal(infoResp)

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
	})
	c.Assert(err, IsNil)

	c.Assert(src.Exists("curl", "latest", "stable"), Equals, true)
	c.Assert(src.Exists("nonexistent", "latest", "stable"), Equals, false)
}

func (s *storeSuite) TestFetchCacheMiss(c *C) {
	tarData := []byte("fake tar.xz content")
	digest := sha384Hash(tarData)

	infoResp := makeBinInfoResponse("curl", "latest", "stable", "amd64", "8.5.0", 42, digest)
	infoBody, _ := json.Marshal(infoResp)

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

	infoResp := makeBinInfoResponse("curl", "latest", "stable", "amd64", "8.5.0", 42, digest)
	infoBody, _ := json.Marshal(infoResp)

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
	infoResp := makeBinInfoResponse("curl", "latest", "stable", "amd64", "8.5.0", 42, "abc123")
	// Override the download URL to an invalid one.
	infoResp.ChannelMap[0].Revision.Download.URL = "http://evil.example.com/bins/curl.tar.xz"
	infoBody, _ := json.Marshal(infoResp)

	s.fakeDoFunc = func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(infoBody)),
		}, nil
	}

	src, err := store.Open(&store.Options{
		Arch:     "amd64",
		CacheDir: s.cacheDir,
	})
	c.Assert(err, IsNil)

	_, _, err = src.Fetch("curl", "latest", "stable")
	c.Assert(err, NotNil)
	c.Assert(err.Error(), testutil.Contains, "must use HTTPS")
}

func (s *storeSuite) TestStagingEnvVar(c *C) {
	s.envRestore()
	s.envRestore = fakeEnv("1")

	src, err := store.Open(&store.Options{
		Arch:     "amd64",
		CacheDir: s.cacheDir,
	})
	c.Assert(err, IsNil)

	infoResp := makeBinInfoResponse("curl", "latest", "stable", "amd64", "8.5.0", 42, "abc123")
	infoBody, _ := json.Marshal(infoResp)

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
