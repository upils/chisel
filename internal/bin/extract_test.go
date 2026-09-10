package bin_test

import (
	"bytes"
	"io"

	. "gopkg.in/check.v1"

	"github.com/canonical/chisel/internal/bin"
	"github.com/canonical/chisel/internal/tarball"
	"github.com/canonical/chisel/internal/testutil"
)

// Compile-time check that Pkg implements tarball.PkgReader.
var _ tarball.PkgReader = (*bin.Pkg)(nil)

func (s *S) TestPkgTarStream(c *C) {
	pkg := bin.OpenPkg(testutil.ReadSeekNopCloser(
		bytes.NewReader(testutil.MustMakeBin([]testutil.TarEntry{
			testutil.Dir(0o755, "./"),
			testutil.Reg(0o644, "./file", "content"),
		}))))

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

func (s *S) TestPkgTarStreamInvalid(c *C) {
	pkg := bin.OpenPkg(testutil.ReadSeekNopCloser(
		bytes.NewReader([]byte("not an xz stream"))))

	_, err := pkg.TarStream()
	c.Assert(err, ErrorMatches, "xz.*")
}
