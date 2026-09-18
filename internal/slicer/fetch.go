package slicer

import (
	"fmt"
	"slices"

	"github.com/canonical/chisel/internal/archive"
	"github.com/canonical/chisel/internal/manifestutil"
	"github.com/canonical/chisel/internal/setup"
	"github.com/canonical/chisel/internal/store"
	"github.com/canonical/chisel/internal/tarball"
)

type Fetcher interface {
	Arch() string
	Fetch() (tarball.PkgReader, manifestutil.PackageInfo, error)
}

var (
	_ Fetcher = (*debFetcher)(nil)
	_ Fetcher = (*binFetcher)(nil)
)

// debFetcher fetches deb packages from an archive.
type debFetcher struct {
	archive archive.Archive
	name    string
}

func (d *debFetcher) Arch() string {
	return d.archive.Options().Arch
}

func (d *debFetcher) Fetch() (tarball.PkgReader, manifestutil.PackageInfo, error) {
	return d.archive.Fetch(d.name)
}

// binFetcher fetches bin packages from a store.
type binFetcher struct {
	name  string
	store store.Store
	track string
	risk  string
}

func (b *binFetcher) Arch() string {
	return b.store.Options().Arch
}

func (b *binFetcher) Fetch() (tarball.PkgReader, manifestutil.PackageInfo, error) {
	return b.store.Fetch(b.name, b.track, b.risk)
}

// selectPkgFetchers determines the fetcher for each package in the selection.
// For packages from an archive it selects the highest priority archive
// containing the package unless a particular archive is pinned within the
// package slices file. For packages from a store it selects the store
// named in the package slices file. It returns a map of Fetcher indexed
// by package names.
func selectPkgFetchers(archives map[string]archive.Archive, stores map[string]store.Store, selection *setup.Selection) (map[string]Fetcher, error) {
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

	fetchers := make(map[string]Fetcher)
	for _, s := range selection.Slices {
		if _, ok := fetchers[s.Package]; ok {
			continue
		}
		pkg := selection.Release.Packages[s.Package]
		if pkg.Store != "" {
			storeHandle := stores[pkg.Store]
			if storeHandle == nil {
				return nil, fmt.Errorf("internal error: no store handle for store %q", pkg.Store)
			}
			
			var channel setup.Channel
			var ok bool
			channel, ok = selection.Channels[pkg.Name]
			if !ok {
				channel.Track = pkg.DefaultTrack
			}

			fetchers[pkg.Name] = &binFetcher{
				name:  pkg.RealName,
				store: storeHandle,
				track: channel.Track,
				risk: channel.Risk,
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
			return nil, fmt.Errorf("cannot find package %q in archive(s)", pkg.RealName)
		}
		fetchers[pkg.Name] = &debFetcher{
			archive: chosen,
			name:    pkg.RealName,
		}
	}

	return fetchers, nil
}
