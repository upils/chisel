package testutil

import (
	"bytes"
	"io"
)

// TestPkg is a tarball.PkgReader over an in-memory tar stream built from
// the given entries.
type TestPkg struct {
	tarData []byte
}

// NewTestPkg returns a TestPkg holding a tar stream with the given entries.
func NewTestPkg(entries ...TarEntry) *TestPkg {
	data, err := makeTar(entries)
	if err != nil {
		panic(err)
	}
	return &TestPkg{tarData: data}
}

// TarStream returns a fresh reader over the tar stream.
func (p *TestPkg) TarStream() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(p.tarData)), nil
}

func (p *TestPkg) Close() error {
	return nil
}
