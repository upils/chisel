package store

import (
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

// Store provides access to packages from the Snapcraft store API.
type Store interface {
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
}

type storeKind string

const storeKindBin storeKind = "bin"

// defaultRisk is the channel risk used when a specific risk has not been
// requested.
const defaultRisk = "stable"

type binStore struct {
	options Options
	cache   *cache.Cache
	apiURL  string
}

const (
	binAPIBase       = "https://api.snapcraft.io/v2/bins"
	binAPIStaging    = "https://api.staging.snapcraft.io/v2/bins"
	binStagingEnvVar = "CHISEL_BIN_STAGING"
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
		if os.Getenv(binStagingEnvVar) != "" {
			apiURL = binAPIStaging
		}
		return &binStore{
			options: *options,
			cache:   &cache.Cache{Dir: options.CacheDir},
			apiURL:  apiURL,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported store kind %q", options.Kind)
	}
}

// binInfoResponse represents the JSON response from the bin store info endpoint.
type binInfoResponse struct {
	Name       string          `json:"name"`
	PackageID  string          `json:"package-id"`
	ChannelMap []binChannelMap `json:"channel-map"`
}

type binChannelMap struct {
	Channel  binChannel  `json:"channel"`
	Revision binRevision `json:"revision"`
}

type binChannel struct {
	Name     string      `json:"name"`
	Risk     string      `json:"risk"`
	Track    string      `json:"track"`
	Platform binPlatform `json:"platform"`
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
	URL     string `json:"url"`
	SHA3384 string `json:"sha3-384"`
	Size    int64  `json:"size"`
}

func (s *binStore) fetchBinInfo(name string) (*binInfoResponse, error) {
	if !nameExp.MatchString(name) {
		return nil, fmt.Errorf("invalid package name %q", name)
	}
	u, err := url.Parse(s.apiURL)
	if err != nil {
		return nil, fmt.Errorf("internal error: cannot parse bin store URL: %v", err)
	}
	u = u.JoinPath("info", name)
	u.RawQuery = url.Values{
		"fields": {"download,version,revision,channel-map"},
	}.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create HTTP request: %v", err)
	}

	resp, err := httpDo(req)
	if err != nil {
		return nil, fmt.Errorf("cannot talk to bin store: %v", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		// ok
	case 404:
		return nil, fmt.Errorf("bin %q not found", name)
	default:
		return nil, fmt.Errorf("cannot fetch from bin store: %v", resp.Status)
	}

	var info binInfoResponse
	err = json.NewDecoder(resp.Body).Decode(&info)
	if err != nil {
		return nil, fmt.Errorf("cannot decode bin store response: %v", err)
	}
	return &info, nil
}

// selectRevision finds the channel-map entry matching the requested track,
// risk, and architecture, returning its revision. An empty risk falls back to
// defaultRisk.
func selectRevision(info *binInfoResponse, arch, track, risk string) (*binRevision, error) {
	if risk == "" {
		risk = defaultRisk
	}
	for i := range info.ChannelMap {
		entry := &info.ChannelMap[i]
		if entry.Channel.Track != track || entry.Channel.Risk != risk {
			continue
		}
		if entry.Channel.Platform.Architecture != arch {
			continue
		}
		return &entry.Revision, nil
	}
	return nil, fmt.Errorf("bin %q has no %s/%s release for architecture %q", info.Name, track, risk, arch)
}

// nameExp matches a valid package name. It deliberately forbids "/" and any
// leading "." so that a name cannot be used to traverse or otherwise alter the
// store API URL path when interpolated into it.
var nameExp = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)

// allowedDownloadHosts lists the hosts from which bin downloads are permitted.
var allowedDownloadHosts = []string{
	"api.snapcraft.io",
	"api.staging.snapcraft.io",
	"storage.snapcraftcontent.com",
}

// validateDownloadURL checks that the download URL is HTTPS and from an
// allowed host.
func validateDownloadURL(downloadURL string) error {
	u, err := url.Parse(downloadURL)
	if err != nil {
		return fmt.Errorf("cannot parse bin download URL: %v", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("bin download URL must use HTTPS: %q", downloadURL)
	}
	for _, host := range allowedDownloadHosts {
		if u.Host == host || strings.HasSuffix(u.Host, "."+host) {
			return nil
		}
	}
	return fmt.Errorf("bin download URL has untrusted host %q", u.Host)
}

func (s *binStore) Info(name, track, risk string) (*StorePackageInfo, error) {
	resp, err := s.fetchBinInfo(name)
	if err != nil {
		return nil, err
	}
	rev, err := selectRevision(resp, s.options.Arch, track, risk)
	if err != nil {
		return nil, err
	}
	return &StorePackageInfo{
		Name:     name,
		Version:  rev.Version,
		Revision: rev.Revision,
		SHA384:   rev.Download.SHA3384,
	}, nil
}

func (s *binStore) Exists(name, track, risk string) bool {
	_, err := s.Info(name, track, risk)
	return err == nil
}

func (s *binStore) Fetch(name, track, risk string) (io.ReadSeekCloser, *StorePackageInfo, error) {
	logf("Fetching bin %s %s/%s ...", name, track, risk)

	resp, err := s.fetchBinInfo(name)
	if err != nil {
		return nil, nil, err
	}
	rev, err := selectRevision(resp, s.options.Arch, track, risk)
	if err != nil {
		return nil, nil, err
	}

	info := &StorePackageInfo{
		Name:     name,
		Version:  rev.Version,
		Revision: rev.Revision,
		SHA384:   rev.Download.SHA3384,
	}

	// Check cache first.
	reader, err := s.cache.Open(cache.SHA384, rev.Download.SHA3384)
	if err == nil {
		logf("Using cached bin %s", name)
		return reader, info, nil
	} else if err != cache.ErrMiss {
		return nil, nil, err
	}

	// Download the bin.
	err = validateDownloadURL(rev.Download.URL)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequest("GET", rev.Download.URL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create HTTP request: %v", err)
	}

	httpResp, err := bulkDo(req)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot download bin %q: %v", name, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("cannot download bin %q: %v", name, httpResp.Status)
	}

	writer := s.cache.Create(cache.SHA384, rev.Download.SHA3384)
	defer writer.Close()

	_, err = io.Copy(writer, httpResp.Body)
	if err == nil {
		err = writer.Close()
	}
	if err != nil {
		return nil, nil, fmt.Errorf("cannot fetch bin %q: %v", name, err)
	}

	reader, err = s.cache.Open(cache.SHA384, rev.Download.SHA3384)
	if err != nil {
		return nil, nil, err
	}
	return reader, info, nil
}
