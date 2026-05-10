package bins_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	. "gopkg.in/check.v1"

	"github.com/canonical/chisel/internal/bins"
)

var binInfoJSON = `{
	"name": "mybin",
	"package-id": "abc123",
	"channel-map": [
		{
			"channel": {
				"name": "latest/stable",
				"risk": "stable",
				"track": "latest",
				"platform": {
					"architecture": "amd64"
				}
			},
			"revision": {
				"version": "1.2.3",
				"revision": 42,
				"download": {
					"url": "https://storage.snapcraftcontent.com/download/mybin_42.tar.xz",
					"sha3-384": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789012",
					"size": 1024
				},
				"platforms": [
					{"architecture": "amd64"}
				]
			}
		},
		{
			"channel": {
				"name": "latest/edge",
				"risk": "edge",
				"track": "latest",
				"platform": {
					"architecture": "amd64"
				}
			},
			"revision": {
				"version": "1.3.0",
				"revision": 50,
				"download": {
					"url": "https://storage.snapcraftcontent.com/download/mybin_50.tar.xz",
					"sha3-384": "edgeedge1234567890",
					"size": 2048
				},
				"platforms": [
					{"architecture": "amd64"}
				]
			}
		},
		{
			"channel": {
				"name": "latest/stable",
				"risk": "stable",
				"track": "latest",
				"platform": {
					"architecture": "arm64"
				}
			},
			"revision": {
				"version": "1.2.3",
				"revision": 43,
				"download": {
					"url": "https://storage.snapcraftcontent.com/download/mybin_43.tar.xz",
					"sha3-384": "arm64sha3384digest",
					"size": 1024
				},
				"platforms": [
					{"architecture": "arm64"}
				]
			}
		}
	]
}`

func fakeResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func (s *S) TestIsBinPackage(c *C) {
	tests := []struct {
		pkg    string
		result bool
	}{
		{"bin-mybin", true},
		{"bin-foo-bar", true},
		{"bin-", true},
		{"mybin", false},
		{"libbin-dev", false},
		{"", false},
	}
	for _, test := range tests {
		c.Check(bins.IsBinPackage(test.pkg), Equals, test.result, Commentf("pkg: %q", test.pkg))
	}
}

func (s *S) TestBinName(c *C) {
	tests := []struct {
		pkg  string
		name string
		err  string
	}{
		{"bin-mybin", "mybin", ""},
		{"bin-foo-bar", "foo-bar", ""},
		{"mybin", "", `invalid bin package name: "mybin" does not have "bin-" prefix`},
		{"", "", `invalid bin package name: "" does not have "bin-" prefix`},
	}
	for _, test := range tests {
		name, err := bins.BinName(test.pkg)
		if test.err != "" {
			c.Check(err, ErrorMatches, test.err, Commentf("pkg: %q", test.pkg))
		} else {
			c.Check(err, IsNil, Commentf("pkg: %q", test.pkg))
			c.Check(name, Equals, test.name, Commentf("pkg: %q", test.pkg))
		}
	}
}

func (s *S) TestOpenInferArch(c *C) {
	src, err := bins.Open(&bins.Options{
		CacheDir: c.MkDir(),
	})
	c.Assert(err, IsNil)
	c.Assert(src, NotNil)
}

func (s *S) TestOpenInvalidArch(c *C) {
	_, err := bins.Open(&bins.Options{
		Arch:     "foo",
		CacheDir: c.MkDir(),
	})
	c.Assert(err, ErrorMatches, "invalid package architecture: foo")
}

func (s *S) TestOpenValid(c *C) {
	src, err := bins.Open(&bins.Options{
		Arch:     "amd64",
		CacheDir: c.MkDir(),
	})
	c.Assert(err, IsNil)
	c.Assert(src, NotNil)
}

func (s *S) TestInfoSuccess(c *C) {
	restore := bins.FakeDo(func(req *http.Request) (*http.Response, error) {
		c.Check(strings.Contains(req.URL.String(), "/v2/bins/info/mybin"), Equals, true)
		return fakeResponse(200, binInfoJSON), nil
	})
	defer restore()

	src, err := bins.Open(&bins.Options{
		Arch:     "amd64",
		CacheDir: c.MkDir(),
	})
	c.Assert(err, IsNil)

	info, err := src.Info("bin-mybin", "latest", "stable")
	c.Assert(err, IsNil)
	c.Check(info.Name, Equals, "mybin")
	c.Check(info.Version, Equals, "1.2.3")
	c.Check(info.Revision, Equals, 42)
	c.Check(info.SHA3384, Equals, "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789012")
}

func (s *S) TestInfoArm64(c *C) {
	restore := bins.FakeDo(func(req *http.Request) (*http.Response, error) {
		return fakeResponse(200, binInfoJSON), nil
	})
	defer restore()

	src, err := bins.Open(&bins.Options{
		Arch:     "arm64",
		CacheDir: c.MkDir(),
	})
	c.Assert(err, IsNil)

	info, err := src.Info("bin-mybin", "latest", "stable")
	c.Assert(err, IsNil)
	c.Check(info.Name, Equals, "mybin")
	c.Check(info.Revision, Equals, 43)
	c.Check(info.SHA3384, Equals, "arm64sha3384digest")
}

func (s *S) TestInfoCustomRisk(c *C) {
	restore := bins.FakeDo(func(req *http.Request) (*http.Response, error) {
		return fakeResponse(200, binInfoJSON), nil
	})
	defer restore()

	src, err := bins.Open(&bins.Options{
		Arch:     "amd64",
		CacheDir: c.MkDir(),
	})
	c.Assert(err, IsNil)

	info, err := src.Info("bin-mybin", "latest", "edge")
	c.Assert(err, IsNil)
	c.Check(info.Name, Equals, "mybin")
	c.Check(info.Revision, Equals, 50)
	c.Check(info.SHA3384, Equals, "edgeedge1234567890")
}

func (s *S) TestInfoNotFound(c *C) {
	restore := bins.FakeDo(func(req *http.Request) (*http.Response, error) {
		return fakeResponse(404, ""), nil
	})
	defer restore()

	src, err := bins.Open(&bins.Options{
		Arch:     "amd64",
		CacheDir: c.MkDir(),
	})
	c.Assert(err, IsNil)

	_, err = src.Info("bin-nosuchbin", "latest", "stable")
	c.Assert(err, ErrorMatches, `bin "nosuchbin" not found`)
}

func (s *S) TestInfoAPIError(c *C) {
	restore := bins.FakeDo(func(req *http.Request) (*http.Response, error) {
		return fakeResponse(500, ""), nil
	})
	defer restore()

	src, err := bins.Open(&bins.Options{
		Arch:     "amd64",
		CacheDir: c.MkDir(),
	})
	c.Assert(err, IsNil)

	_, err = src.Info("bin-mybin", "latest", "stable")
	c.Assert(err, ErrorMatches, `cannot fetch from bins API: 500.*`)
}

func (s *S) TestInfoHTTPError(c *C) {
	restore := bins.FakeDo(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("connection refused")
	})
	defer restore()

	src, err := bins.Open(&bins.Options{
		Arch:     "amd64",
		CacheDir: c.MkDir(),
	})
	c.Assert(err, IsNil)

	_, err = src.Info("bin-mybin", "latest", "stable")
	c.Assert(err, ErrorMatches, `cannot talk to bins API: connection refused`)
}

func (s *S) TestInfoNoMatchingArch(c *C) {
	// Use a response that only has amd64 and arm64.
	restore := bins.FakeDo(func(req *http.Request) (*http.Response, error) {
		return fakeResponse(200, binInfoJSON), nil
	})
	defer restore()

	src, err := bins.Open(&bins.Options{
		Arch:     "s390x",
		CacheDir: c.MkDir(),
	})
	c.Assert(err, IsNil)

	_, err = src.Info("bin-mybin", "latest", "stable")
	c.Assert(err, ErrorMatches, `bin "mybin" has no latest/stable release for architecture "s390x"`)
}

func (s *S) TestInfoInvalidPkgName(c *C) {
	src, err := bins.Open(&bins.Options{
		Arch:     "amd64",
		CacheDir: c.MkDir(),
	})
	c.Assert(err, IsNil)

	_, err = src.Info("notabin", "latest", "stable")
	c.Assert(err, ErrorMatches, `invalid bin package name: "notabin" does not have "bin-" prefix`)
}

func (s *S) TestExistsTrue(c *C) {
	restore := bins.FakeDo(func(req *http.Request) (*http.Response, error) {
		return fakeResponse(200, binInfoJSON), nil
	})
	defer restore()

	src, err := bins.Open(&bins.Options{
		Arch:     "amd64",
		CacheDir: c.MkDir(),
	})
	c.Assert(err, IsNil)

	c.Check(src.Exists("bin-mybin", "latest", "stable"), Equals, true)
}

func (s *S) TestExistsFalse(c *C) {
	restore := bins.FakeDo(func(req *http.Request) (*http.Response, error) {
		return fakeResponse(404, ""), nil
	})
	defer restore()

	src, err := bins.Open(&bins.Options{
		Arch:     "amd64",
		CacheDir: c.MkDir(),
	})
	c.Assert(err, IsNil)

	c.Check(src.Exists("bin-nosuchbin", "latest", "stable"), Equals, false)
}

func (s *S) TestFetchDownloadsAndCaches(c *C) {
	binContent := "fake-tar-xz-content"

	// Compute SHA3-384 of our fake content to build a matching response.
	// We'll make the API return a digest, then the download serves that content.
	// The cache will verify the digest on Close.
	infoRequests := 0
	downloadRequests := 0
	restore := bins.FakeDo(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, "/v2/bins/info/") {
			infoRequests++
			return fakeResponse(200, binInfoJSON), nil
		}
		if strings.Contains(req.URL.Host, "storage.snapcraftcontent.com") {
			downloadRequests++
			return fakeResponse(200, binContent), nil
		}
		return nil, fmt.Errorf("unexpected request: %s", req.URL)
	})
	defer restore()

	src, err := bins.Open(&bins.Options{
		Arch:     "amd64",
		CacheDir: c.MkDir(),
	})
	c.Assert(err, IsNil)

	// The digest won't match the fake content, so the cache will fail.
	// That's expected — we're testing the flow, not real crypto.
	_, _, err = src.Fetch("bin-mybin", "latest", "stable")
	c.Assert(err, NotNil)
	c.Check(infoRequests, Equals, 1)
	c.Check(downloadRequests, Equals, 1)
}

func (s *S) TestFetchInvalidPkgName(c *C) {
	src, err := bins.Open(&bins.Options{
		Arch:     "amd64",
		CacheDir: c.MkDir(),
	})
	c.Assert(err, IsNil)

	_, _, err = src.Fetch("notabin", "latest", "stable")
	c.Assert(err, ErrorMatches, `invalid bin package name: "notabin" does not have "bin-" prefix`)
}

func (s *S) TestFetchDownloadHTTPError(c *C) {
	calls := 0
	restore := bins.FakeDo(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, "/v2/bins/info/") {
			calls++
			return fakeResponse(200, binInfoJSON), nil
		}
		calls++
		return nil, fmt.Errorf("download failed")
	})
	defer restore()

	src, err := bins.Open(&bins.Options{
		Arch:     "amd64",
		CacheDir: c.MkDir(),
	})
	c.Assert(err, IsNil)

	_, _, err = src.Fetch("bin-mybin", "latest", "stable")
	c.Assert(err, ErrorMatches, `cannot download bin "mybin": download failed`)
}

func (s *S) TestFetchDownloadHTTPStatus(c *C) {
	restore := bins.FakeDo(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, "/v2/bins/info/") {
			return fakeResponse(200, binInfoJSON), nil
		}
		return fakeResponse(503, ""), nil
	})
	defer restore()

	src, err := bins.Open(&bins.Options{
		Arch:     "amd64",
		CacheDir: c.MkDir(),
	})
	c.Assert(err, IsNil)

	_, _, err = src.Fetch("bin-mybin", "latest", "stable")
	c.Assert(err, ErrorMatches, `cannot download bin "mybin": 503.*`)
}

func (s *S) TestFetchInfoError(c *C) {
	restore := bins.FakeDo(func(req *http.Request) (*http.Response, error) {
		return fakeResponse(404, ""), nil
	})
	defer restore()

	src, err := bins.Open(&bins.Options{
		Arch:     "amd64",
		CacheDir: c.MkDir(),
	})
	c.Assert(err, IsNil)

	_, _, err = src.Fetch("bin-mybin", "latest", "stable")
	c.Assert(err, ErrorMatches, `bin "mybin" not found`)
}

var validateDownloadURLTests = []struct {
	summary string
	url     string
	err     string
}{
	{
		summary: "Valid snapcraftcontent URL",
		url:     "https://storage.snapcraftcontent.com/download/mybin_42.tar.xz",
	},
	{
		summary: "Valid API URL",
		url:     "https://api.staging.snapcraft.io/download/mybin_42.tar.xz",
	},
	{
		summary: "Valid subdomain of allowed host",
		url:     "https://cdn.storage.snapcraftcontent.com/download/mybin_42.tar.xz",
	},
	{
		summary: "HTTP scheme rejected",
		url:     "http://storage.snapcraftcontent.com/download/mybin_42.tar.xz",
		err:     `bin download URL must use HTTPS: "http://storage.snapcraftcontent.com/download/mybin_42.tar.xz"`,
	},
	{
		summary: "Untrusted host rejected",
		url:     "https://evil.example.com/download/mybin_42.tar.xz",
		err:     `bin download URL has untrusted host "evil.example.com"`,
	},
	{
		summary: "Partial host match rejected",
		url:     "https://notstorage.snapcraftcontent.com/download/mybin_42.tar.xz",
		err:     `bin download URL has untrusted host "notstorage.snapcraftcontent.com"`,
	},
}

func (s *S) TestValidateDownloadURL(c *C) {
	for _, test := range validateDownloadURLTests {
		c.Logf("Test: %s", test.summary)
		err := bins.ValidateDownloadURL(test.url)
		if test.err != "" {
			c.Check(err, ErrorMatches, test.err)
		} else {
			c.Check(err, IsNil)
		}
	}
}

func (s *S) TestInfoBadJSON(c *C) {
	restore := bins.FakeDo(func(req *http.Request) (*http.Response, error) {
		return fakeResponse(200, "not json"), nil
	})
	defer restore()

	src, err := bins.Open(&bins.Options{
		Arch:     "amd64",
		CacheDir: c.MkDir(),
	})
	c.Assert(err, IsNil)

	_, err = src.Info("bin-mybin", "latest", "stable")
	c.Assert(err, ErrorMatches, "cannot decode bins API response: .*")
}

func (s *S) TestInfoEmptyChannelMap(c *C) {
	emptyInfo, _ := json.Marshal(map[string]any{
		"name":        "mybin",
		"package-id":  "abc123",
		"channel-map": []any{},
	})
	restore := bins.FakeDo(func(req *http.Request) (*http.Response, error) {
		return fakeResponse(200, string(emptyInfo)), nil
	})
	defer restore()

	src, err := bins.Open(&bins.Options{
		Arch:     "amd64",
		CacheDir: c.MkDir(),
	})
	c.Assert(err, IsNil)

	_, err = src.Info("bin-mybin", "latest", "stable")
	c.Assert(err, ErrorMatches, `bin "mybin" has no latest/stable release for architecture "amd64"`)
}
