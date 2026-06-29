package testutil

import (
	"bytes"
	"fmt"
	"io"

	"github.com/canonical/chisel/internal/store"
)

type TestStore struct {
	Opts     store.Options
	Packages map[string]*TestPackage
}

func (s *TestStore) Options() *store.Options {
	return &s.Opts
}

func (s *TestStore) Fetch(name, track, risk string) (io.ReadSeekCloser, *store.StorePackageInfo, error) {
	pkg, ok := s.Packages[name]
	if !ok {
		return nil, nil, fmt.Errorf("cannot find package %q in store", name)
	}
	info := &store.StorePackageInfo{
		Name:    pkg.Name,
		Version: pkg.Version,
		SHA384:  pkg.Hash,
	}
	return ReadSeekNopCloser(bytes.NewReader(pkg.Data)), info, nil
}
