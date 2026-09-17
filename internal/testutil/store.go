package testutil

import (
	"bytes"
	"fmt"

	"github.com/canonical/chisel/internal/bin"
	"github.com/canonical/chisel/internal/manifestutil"
	"github.com/canonical/chisel/internal/store"
	"github.com/canonical/chisel/internal/tarball"
)

type TestStore struct {
	Opts     store.Options
	Packages map[string]*BinPackage
}

func (s *TestStore) Options() *store.Options {
	return &s.Opts
}

func (s *TestStore) Fetch(name, track, risk string) (tarball.PkgReader, manifestutil.PackageInfo, error) {
	pkg, ok := s.Packages[name]
	if !ok {
		return nil, nil, fmt.Errorf("cannot find package %q in store", name)
	}
	return bin.OpenPkg(ReadSeekNopCloser(bytes.NewReader(pkg.Data))), pkg.info(), nil
}
