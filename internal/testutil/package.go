package testutil

import (
	"github.com/canonical/chisel/internal/archive"
	"github.com/canonical/chisel/internal/store"
)

// DebPackage is a fixture for a deb package, served by a TestArchive.
type DebPackage struct {
	Name string
	Data []byte
	// Info is the metadata reported for the package when it is fetched.
	// Fields left empty are filled with defaults which satisfy the manifest
	// validation. The package name is always taken from Name.
	Info archive.PackageInfo
	// Archives lists the archives the package belongs to. When empty, the
	// package belongs to all archives.
	Archives []string
}

// info returns the metadata to report when the package is fetched.
func (p *DebPackage) info() *archive.PackageInfo {
	info := p.Info
	if info.Version == "" {
		info.Version = "version"
	}
	if info.Arch == "" {
		info.Arch = "arch"
	}
	if info.SHA256 == "" {
		info.SHA256 = "hash"
	}
	info.Name = p.Name
	return &info
}

// BinPackage is a fixture for a bin package, served by a TestStore.
type BinPackage struct {
	Name string
	Data []byte
	// Info is the metadata reported for the package when it is fetched.
	// Fields left empty are filled with defaults which satisfy the manifest
	// validation. The package name is always taken from Name.
	Info store.PackageInfo
	// Store names the store the package is served from.
	Store string
}

// info returns the metadata to report when the package is fetched.
func (p *BinPackage) info() *store.PackageInfo {
	info := p.Info
	if info.Version == "" {
		info.Version = "version"
	}
	if info.Arch == "" {
		info.Arch = "arch"
	}
	if info.SHA384 == "" {
		info.SHA384 = "hash"
	}
	info.Name = p.Name
	return &info
}
