package testutil

import (
	"bytes"
	"fmt"
	"io"

	"github.com/canonical/chisel/internal/manifestutil"
	"github.com/canonical/chisel/internal/store"
)

type TestStore struct {
	Opts     store.Options
	Packages map[string]*BinPackage
}

func (s *TestStore) Options() *store.Options {
	return &s.Opts
}

func (s *TestStore) Fetch(name, track, risk string) (io.ReadSeekCloser, manifestutil.PackageInfo, error) {
	pkg, ok := s.Packages[name]
	if !ok {
		return nil, nil, fmt.Errorf("cannot find package %q in store", name)
	}
	return ReadSeekNopCloser(bytes.NewReader(pkg.Data)), pkg.info(), nil
}
