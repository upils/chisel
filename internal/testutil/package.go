package testutil

// TestPackage is a source-agnostic package fixture that can be served by either
// a TestArchive or a TestStore.
type TestPackage struct {
	Name    string
	Version string
	Hash    string
	Arch    string
	Data    []byte
	// Archives lists the archives the package belongs to. It is only relevant
	// for archive-backed packages.
	Archives []string
	// Store names the store the package is served from. When set, the package
	// is store-backed rather than archive-backed.
	Store string
}
