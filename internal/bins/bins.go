package bins

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/canonical/chisel/internal/cache"
	"github.com/canonical/chisel/internal/deb"
)

const binsAPIBase = "https://api.staging.snapcraft.io/v2/bins"

// BinPackageInfo holds metadata about a bin package.
type BinPackageInfo struct {
	Name     string
	Version  string
	Revision int
	SHA3384  string
}

// Source provides access to bin packages from the Snapcraft store API.
type Source interface {
	Fetch(pkg, track, risk string) (io.ReadSeekCloser, *BinPackageInfo, error)
	Exists(pkg, track, risk string) bool
	Info(pkg, track, risk string) (*BinPackageInfo, error)
}

// Options configures a bin source.
type Options struct {
	Arch     string
	CacheDir string
}

type binSource struct {
	options Options
	cache   *cache.Cache
}

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

var httpDo = httpClient.Do

var bulkClient = &http.Client{
	Timeout: 5 * time.Minute,
}

var bulkDo = bulkClient.Do

// Open creates a new bin source with the given options.
func Open(options *Options) (Source, error) {
	var err error
	if options.Arch == "" {
		options.Arch, err = deb.InferArch()
	} else {
		err = deb.ValidateArch(options.Arch)
	}
	if err != nil {
		return nil, err
	}
	return &binSource{
		options: *options,
		cache: &cache.Cache{
			Dir: options.CacheDir,
		},
	}, nil
}

// IsBinPackage reports whether the given package name refers to a bin package
// (i.e. it is prefixed with "bin-").
func IsBinPackage(pkg string) bool {
	return strings.HasPrefix(pkg, "bin-")
}

// BinName returns the API name for a bin package by stripping the "bin-" prefix.
// It returns an error if the package name does not have the expected prefix.
func BinName(pkg string) (string, error) {
	if !IsBinPackage(pkg) {
		return "", fmt.Errorf("invalid bin package name: %q does not have \"bin-\" prefix", pkg)
	}
	return strings.TrimPrefix(pkg, "bin-"), nil
}

// binInfoResponse represents the JSON response from the bins info endpoint.
type binInfoResponse struct {
	Name       string `json:"name"`
	PackageID  string `json:"package-id"`
	ChannelMap []struct {
		Channel struct {
			Name     string `json:"name"`
			Risk     string `json:"risk"`
			Track    string `json:"track"`
			Platform struct {
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"channel"`
		Revision struct {
			Version  string `json:"version"`
			Revision int    `json:"revision"`
			Download struct {
				URL     string `json:"url"`
				SHA3384 string `json:"sha3-384"`
				Size    int64  `json:"size"`
			} `json:"download"`
			Platforms []struct {
				Architecture string `json:"architecture"`
			} `json:"platforms"`
		} `json:"revision"`
	} `json:"channel-map"`
}

// debArchToSnapArch maps Debian-style architecture names to snap-style ones.
func debArchToSnapArch(arch string) string {
	switch arch {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	case "armhf":
		return "armhf"
	case "i386":
		return "i386"
	case "ppc64el":
		return "ppc64el"
	case "s390x":
		return "s390x"
	case "riscv64":
		return "riscv64"
	default:
		return arch
	}
}

// fetchBinInfo calls the Snapcraft bins info API for the given bin name.
func fetchBinInfo(name, arch string) (*binInfoResponse, error) {
	apiURL, err := url.JoinPath(binsAPIBase, "info", name)
	if err != nil {
		return nil, fmt.Errorf("internal error: cannot construct bins API URL: %v", err)
	}
	apiURL += "?fields=download,version,revision,channel-map"

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create HTTP request: %v", err)
	}

	resp, err := httpDo(req)
	if err != nil {
		return nil, fmt.Errorf("cannot talk to bins API: %v", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		// ok
	case 404:
		return nil, fmt.Errorf("bin %q not found", name)
	default:
		return nil, fmt.Errorf("cannot fetch from bins API: %v", resp.Status)
	}

	var info binInfoResponse
	err = json.NewDecoder(resp.Body).Decode(&info)
	if err != nil {
		return nil, fmt.Errorf("cannot decode bins API response: %v", err)
	}
	return &info, nil
}

// selectRevision finds the channel-map entry matching the requested track,
// risk, and architecture.
func selectRevision(info *binInfoResponse, arch, track, risk string) (downloadURL, sha3384, version string, revision int, err error) {
	snapArch := debArchToSnapArch(arch)
	for _, entry := range info.ChannelMap {
		if entry.Channel.Track != track || entry.Channel.Risk != risk {
			continue
		}
		if entry.Channel.Platform.Architecture != snapArch {
			continue
		}
		return entry.Revision.Download.URL, entry.Revision.Download.SHA3384, entry.Revision.Version, entry.Revision.Revision, nil
	}
	return "", "", "", 0, fmt.Errorf("bin %q has no %s/%s release for architecture %q", info.Name, track, risk, arch)
}

// allowedDownloadHosts lists the hosts from which bin downloads are permitted.
var allowedDownloadHosts = []string{
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

func (s *binSource) Info(pkg, track, risk string) (*BinPackageInfo, error) {
	name, err := BinName(pkg)
	if err != nil {
		return nil, err
	}
	resp, err := fetchBinInfo(name, s.options.Arch)
	if err != nil {
		return nil, err
	}
	_, sha3384, version, revision, err := selectRevision(resp, s.options.Arch, track, risk)
	if err != nil {
		return nil, err
	}
	return &BinPackageInfo{
		Name:     name,
		Version:  version,
		Revision: revision,
		SHA3384:  sha3384,
	}, nil
}

func (s *binSource) Exists(pkg, track, risk string) bool {
	_, err := s.Info(pkg, track, risk)
	return err == nil
}

func (s *binSource) Fetch(pkg, track, risk string) (io.ReadSeekCloser, *BinPackageInfo, error) {
	name, err := BinName(pkg)
	if err != nil {
		return nil, nil, err
	}
	logf("Fetching bin %s info...", name)

	resp, err := fetchBinInfo(name, s.options.Arch)
	if err != nil {
		return nil, nil, err
	}
	downloadURL, sha3384, version, revision, err := selectRevision(resp, s.options.Arch, track, risk)
	if err != nil {
		return nil, nil, err
	}

	info := &BinPackageInfo{
		Name:     name,
		Version:  version,
		Revision: revision,
		SHA3384:  sha3384,
	}

	// Check cache first.
	reader, err := s.cache.OpenWithAlgo(cache.SHA3384, sha3384)
	if err == nil {
		logf("Using cached bin %s", name)
		return reader, info, nil
	} else if err != cache.MissErr {
		return nil, nil, err
	}

	// Download the bin.
	err = validateDownloadURL(downloadURL)
	if err != nil {
		return nil, nil, err
	}
	logf("Downloading bin %s...", name)
	req, err := http.NewRequest("GET", downloadURL, nil)
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

	writer := s.cache.CreateWithAlgo(cache.SHA3384, sha3384)
	defer writer.Close()

	_, err = io.Copy(writer, httpResp.Body)
	if err == nil {
		err = writer.Close()
	}
	if err != nil {
		return nil, nil, fmt.Errorf("cannot fetch bin %q: %v", name, err)
	}

	reader, err = s.cache.OpenWithAlgo(cache.SHA3384, writer.Digest())
	if err != nil {
		return nil, nil, err
	}
	return reader, info, nil
}
