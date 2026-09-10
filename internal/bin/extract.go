package bin

import (
	"io"

	"github.com/ulikunitz/xz"
)

// Pkg reads the tar stream of a bin package held in a seekable reader.
// A bin package is a plain XZ-compressed tarball.
type Pkg struct {
	reader io.ReadSeekCloser
}

// OpenPkg wraps a seekable reader over bin package data.
func OpenPkg(reader io.ReadSeekCloser) *Pkg {
	return &Pkg{reader: reader}
}

// TarStream returns a reader over the tar stream of the bin package,
// reading from the current position.
func (p *Pkg) TarStream() (io.ReadCloser, error) {
	xzReader, err := xz.NewReader(p.reader)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(xzReader), nil
}

func (p *Pkg) Seek(offset int64, whence int) (int64, error) {
	return p.reader.Seek(offset, whence)
}

func (p *Pkg) Close() error {
	return p.reader.Close()
}
