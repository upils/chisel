package deb_test

import (
	"bytes"
	"io"

	. "gopkg.in/check.v1"

	"github.com/canonical/chisel/internal/deb"
	"github.com/canonical/chisel/internal/tarball"
	"github.com/canonical/chisel/internal/testutil"
)

// Compile-time check that Pkg implements tarball.PkgReader.
var _ tarball.PkgReader = (*deb.Pkg)(nil)

func (s *S) TestPkgTarStream(c *C) {
	pkg := deb.OpenPkg(testutil.ReadSeekNopCloser(
		bytes.NewReader(testutil.PackageData["test-package"])))

	tarStream, err := pkg.TarStream()
	c.Assert(err, IsNil)
	err = tarStream.Close()
	c.Assert(err, IsNil)

	// A second stream can be obtained after rewinding.
	_, err = pkg.Seek(0, io.SeekStart)
	c.Assert(err, IsNil)
	tarStream, err = pkg.TarStream()
	c.Assert(err, IsNil)
	err = tarStream.Close()
	c.Assert(err, IsNil)
}
