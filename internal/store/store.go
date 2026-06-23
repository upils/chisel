package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/canonical/chisel/internal/cache"
	"github.com/canonical/chisel/internal/deb"
)

// Store provides access to packages from the Store API.
type Store interface {
	Options() *Options
	Fetch(name, track, risk string) (io.ReadSeekCloser, *StorePackageInfo, error)
	Exists(name, track, risk string) bool
	Info(name, track, risk string) (*StorePackageInfo, error)
}

// StorePackageInfo holds metadata about a package.
type StorePackageInfo struct {
	Name     string
	Version  string
	Revision int
	SHA384   string
}

type Options struct {
	Arch     string
	CacheDir string
	Kind     string
	Version  string
}

type storeKind string

const storeKindBin storeKind = "bin"

const defaultRisk = "stable"

type binStore struct {
	options      Options
	cache        *cache.Cache
	apiURL       string
	downloadHost string
}

const (
	binAPIBase             = "https://api.snapcraft.io/v2"
	binAPIBaseStaging      = "https://api.staging.snapcraft.io/v2"
	binDownloadHost        = "api.snapcraft.io"
	binDownloadHostStaging = "api.staging.snapcraft.io"
	binStagingEnvVar       = "CHISEL_BIN_STAGING"
)

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

var httpDo = httpClient.Do

var bulkClient = &http.Client{
	Timeout: 5 * time.Minute,
}

var bulkDo = bulkClient.Do

func Open(options *Options) (Store, error) {
	var err error
	if options.Arch == "" {
		options.Arch, err = deb.InferArch()
	} else {
		err = deb.ValidateArch(options.Arch)
	}
	if err != nil {
		return nil, err
	}

	switch storeKind(options.Kind) {
	case storeKindBin:
		apiURL := binAPIBase
		downloadHost := binDownloadHost
		if os.Getenv(binStagingEnvVar) != "" {
			apiURL = binAPIBaseStaging
			downloadHost = binDownloadHostStaging
		}
		return &binStore{
			options:      *options,
			cache:        &cache.Cache{Dir: options.CacheDir},
			apiURL:       apiURL,
			downloadHost: downloadHost,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported store kind %q", options.Kind)
	}
}

// resolveRequest is the body sent to the revisions/resolve endpoint.
type resolveRequest struct {
	Packages []resolvePackage `json:"packages"`
}

type resolvePackage struct {
	InstanceKey string      `json:"instance-key"`
	Namespace   string      `json:"namespace"`
	Name        string      `json:"name"`
	Channel     string      `json:"channel"`
	Platform    binPlatform `json:"platform"`
}

type resolveResponse struct {
	PackageResults []resolveResult `json:"package-results"`
}

type resolveResult struct {
	InstanceKey string        `json:"instance-key"`
	Status      string        `json:"status"`
	Error       *resolveError `json:"error"`
	Result      *resolveEntry `json:"result"`
}

type resolveError struct {
	Message string `json:"message"`
}

type resolveEntry struct {
	Revision binRevision `json:"revision"`
}

type binPlatform struct {
	Architecture string `json:"architecture"`
}

type binRevision struct {
	Version  string      `json:"version"`
	Revision int         `json:"revision"`
	Download binDownload `json:"download"`
}

type binDownload struct {
	URL    string `json:"url"`
	SHA384 string `json:"sha3-384"`
}

// resolveRevision resolves a single package revision via the store API. It
// returns the matching revision or an error if the package is not found or has
// no release for the requested channel and architecture.
func (s *binStore) resolveRevision(name, track, risk string) (*binRevision, error) {
	if !nameExp.MatchString(name) {
		return nil, fmt.Errorf("invalid package name %q", name)
	}
	u, err := url.Parse(s.apiURL)
	if err != nil {
		return nil, fmt.Errorf("internal error: cannot parse bin store URL: %v", err)
	}
	u = u.JoinPath("revisions", "resolve")

	reqBody, err := json.Marshal(resolveRequest{
		Packages: []resolvePackage{{
			InstanceKey: name,
			Namespace:   string(storeKindBin),
			Name:        name,
			Channel:     track + "/" + risk,
			Platform:    binPlatform{Architecture: s.options.Arch},
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("internal error: cannot encode resolve request: %v", err)
	}

	req, err := http.NewRequest("POST", u.String(), bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("cannot create HTTP request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := httpDo(req)
	if err != nil {
		return nil, fmt.Errorf("cannot talk to store: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("cannot fetch from store: %v", resp.Status)
	}

	var res resolveResponse
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return nil, fmt.Errorf("cannot decode store response: %v", err)
	}

	if len(res.PackageResults) == 0 {
		return nil, fmt.Errorf("package %q not found", name)
	}
	if len(res.PackageResults) > 1 {
		return nil, fmt.Errorf("internal error: store returned %d results for package %q", len(res.PackageResults), name)
	}
	result := &res.PackageResults[0]
	if result.Status != "ok" || result.Result == nil {
		if result.Error != nil {
			return nil, fmt.Errorf("package %q not found: %s", name, result.Error.Message)
		}
		return nil, fmt.Errorf("package %q not found", name)
	}
	rev := &result.Result.Revision
	if rev.Download.SHA384 == "" {
		return nil, fmt.Errorf("package %q has no download digest", name)
	}
	return rev, nil
}

// nameExp matches a valid package name. It deliberately forbids "/" and any
// leading "." so that a name cannot be used to traverse or otherwise alter the
// store API URL path when interpolated into it.
var nameExp = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)

// validateDownloadURL checks that the download URL is HTTPS and from the
// allowed host.
func validateDownloadURL(downloadURL, allowedHost string) error {
	u, err := url.Parse(downloadURL)
	if err != nil {
		return fmt.Errorf("cannot parse download URL: %v", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("download URL must use HTTPS: %q", downloadURL)
	}
	host := strings.ToLower(u.Hostname())
	if host == allowedHost || strings.HasSuffix(host, "."+allowedHost) {
		return nil
	}
	return fmt.Errorf("download URL has untrusted host %q", host)
}

func (s *binStore) Options() *Options {
	return &s.options
}

func (s *binStore) Info(name, track, risk string) (*StorePackageInfo, error) {
	if risk == "" {
		risk = defaultRisk
	}
	rev, err := s.resolveRevision(name, track, risk)
	if err != nil {
		return nil, err
	}
	return &StorePackageInfo{
		Name:     name,
		Version:  rev.Version,
		Revision: rev.Revision,
		SHA384:   rev.Download.SHA384,
	}, nil
}

func (s *binStore) Exists(name, track, risk string) bool {
	_, err := s.Info(name, track, risk)
	return err == nil
}

func (s *binStore) Fetch(name, track, risk string) (io.ReadSeekCloser, *StorePackageInfo, error) {
	if risk == "" {
		risk = defaultRisk
	}
	logf("Fetching package %s %s/%s...", name, track, risk)

	rev, err := s.resolveRevision(name, track, risk)
	if err != nil {
		return nil, nil, err
	}

	digest := rev.Download.SHA384
	info := &StorePackageInfo{
		Name:     name,
		Version:  rev.Version,
		Revision: rev.Revision,
		SHA384:   rev.Download.SHA384,
	}

	const digestKind = cache.SHA384
	// Check cache first.
	reader, err := s.cache.Open(digestKind, digest)
	if err == nil {
		logf("Using cached package %s", name)
		return reader, info, nil
	} else if err != cache.ErrMiss {
		return nil, nil, err
	}

	// Download the package.
	err = validateDownloadURL(rev.Download.URL, s.downloadHost)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequest("GET", rev.Download.URL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create HTTP request: %v", err)
	}

	httpResp, err := bulkDo(req)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot download package %q: %v", name, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("cannot download package %q: %v", name, httpResp.Status)
	}

	writer := s.cache.Create(digestKind, digest)
	defer writer.Close()

	_, err = io.Copy(writer, httpResp.Body)
	if err == nil {
		err = writer.Close()
	}
	if err != nil {
		return nil, nil, fmt.Errorf("cannot fetch package %q: %v", name, err)
	}

	reader, err = s.cache.Open(digestKind, writer.Digest())
	if err != nil {
		return nil, nil, err
	}
	return reader, info, nil
}
