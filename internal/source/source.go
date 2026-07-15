package source

import (
	"fmt"
	"io"
	"slices"

	"github.com/canonical/chisel/internal/archive"
	"github.com/canonical/chisel/internal/setup"
)

// Source is a package source that can be fetched. It is implemented by
// archives and stores.
type Source interface {
	Arch() string
	Fetch(opts FetchOption) (io.ReadSeekCloser, *archive.PackageInfo, error)
}

// FetchOption carries source-specific arguments for fetching a package.
// Concrete types are defined in this package to keep the interface sealed.
type FetchOption interface {
	isFetchOption()
}

// ArchiveFetch carries the arguments for fetching a package from an archive.
type ArchiveFetch struct {
	Name string
}

func (ArchiveFetch) isFetchOption() {}

// StoreFetch carries the arguments for fetching a package from a store.
type StoreFetch struct {
	Name  string
	Store string
	Track string
}

func (StoreFetch) isFetchOption() {}

// archiveSource adapts an archive.Archive to the Source interface.
type archiveSource struct {
	archive archive.Archive
}

func (a *archiveSource) Arch() string {
	return a.archive.Options().Arch
}

func (a *archiveSource) Fetch(opts FetchOption) (io.ReadSeekCloser, *archive.PackageInfo, error) {
	archiveOpts, ok := opts.(ArchiveFetch)
	if !ok {
		return nil, nil, fmt.Errorf("internal error: invalid fetch option %T for archive source", opts)
	}
	return a.archive.Fetch(archiveOpts.Name)
}

// storeSource is a Source backed by a store. Store support is not yet
// implemented, so Fetch always returns an error.
type storeSource struct {
	arch string
}

func (s *storeSource) Arch() string {
	return s.arch
}

func (s *storeSource) Fetch(opts FetchOption) (io.ReadSeekCloser, *archive.PackageInfo, error) {
	storeOpts, ok := opts.(StoreFetch)
	if !ok {
		return nil, nil, fmt.Errorf("internal error: invalid fetch option %T for store source", opts)
	}
	return nil, nil, fmt.Errorf("cannot fetch package %q from store %q: not implemented", storeOpts.Name, storeOpts.Store)
}

// Resolve determines the source and fetch options for each package in the
// selection. For archive packages it selects the highest priority archive
// containing the package unless a particular archive is pinned within the
// slice definition file. It returns a map of Source and a map of FetchOption,
// both indexed by package name.
func Resolve(archives map[string]archive.Archive, selection *setup.Selection) (map[string]Source, map[string]FetchOption, error) {
	sortedArchives := make([]*setup.Archive, 0, len(selection.Release.Archives))
	for _, archive := range selection.Release.Archives {
		if archive.Priority < 0 {
			// Ignore negative priority archives unless a package specifically
			// asks for it with the "archive" field.
			continue
		}
		sortedArchives = append(sortedArchives, archive)
	}
	slices.SortFunc(sortedArchives, func(a, b *setup.Archive) int {
		return b.Priority - a.Priority
	})

	sources := make(map[string]Source)
	fetchOpts := make(map[string]FetchOption)
	for _, s := range selection.Slices {
		if _, ok := sources[s.Package]; ok {
			continue
		}
		pkg := selection.Release.Packages[s.Package]
		if pkg.Store != "" {
			sources[pkg.Name] = &storeSource{}
			fetchOpts[pkg.Name] = StoreFetch{
				Name:  pkg.Name,
				Store: pkg.Store,
				Track: pkg.DefaultTrack,
			}
			continue
		}

		var candidates []*setup.Archive
		if pkg.Archive == "" {
			// If the package has not pinned any archive, choose the highest
			// priority archive in which the package exists.
			candidates = sortedArchives
		} else {
			candidates = []*setup.Archive{selection.Release.Archives[pkg.Archive]}
		}

		var chosen archive.Archive
		for _, archiveInfo := range candidates {
			archive := archives[archiveInfo.Name]
			if archive != nil && archive.Exists(pkg.RealName) {
				chosen = archive
				break
			}
		}
		if chosen == nil {
			return nil, nil, fmt.Errorf("cannot find package %q in archive(s)", pkg.RealName)
		}
		sources[pkg.Name] = &archiveSource{archive: chosen}
		fetchOpts[pkg.Name] = ArchiveFetch{Name: pkg.RealName}
	}

	// Until a store is implemented as a package source there is no proper way
	// to determine the architecture for store packages. So relying on the fact
	// that all packages in a selection share the same architecture, we can
	// borrow it from any archive package that was already resolved.
	var arch string
	for _, src := range sources {
		if _, ok := src.(*storeSource); !ok {
			arch = src.Arch()
			break
		}
	}
	for name, src := range sources {
		if ss, ok := src.(*storeSource); ok {
			ss.arch = arch
			sources[name] = src
		}
	}

	return sources, fetchOpts, nil
}
