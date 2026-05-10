package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/sha3"
)

// HashAlgorithm identifies the hash algorithm used for cache entries.
type HashAlgorithm string

const (
	SHA256  HashAlgorithm = "sha256"
	SHA3384 HashAlgorithm = "sha3-384"
)

func newHash(algo HashAlgorithm) (hash.Hash, error) {
	switch algo {
	case SHA256:
		return sha256.New(), nil
	case SHA3384:
		return sha3.New384(), nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", algo)
	}
}

func DefaultDir(suffix string) string {
	cacheDir := os.Getenv("XDG_CACHE_HOME")
	if cacheDir == "" {
		homeDir := os.Getenv("HOME")
		if homeDir != "" {
			cacheDir = filepath.Join(homeDir, ".cache")
		} else {
			var err error
			cacheDir, err = os.MkdirTemp("", "cache-*")
			if err != nil {
				panic("no proper location for cache: " + err.Error())
			}
		}
	}
	return filepath.Join(cacheDir, suffix)
}

type Cache struct {
	Dir string
}

type Writer struct {
	dir    string
	algo   HashAlgorithm
	digest string
	hash   hash.Hash
	file   *os.File
	err    error
}

func (cw *Writer) fail(err error) error {
	if cw.err == nil {
		cw.err = err
		cw.file.Close()
		os.Remove(cw.file.Name())
	}
	return err
}

func (cw *Writer) Write(data []byte) (n int, err error) {
	if cw.err != nil {
		return 0, cw.err
	}
	n, err = cw.file.Write(data)
	if err != nil {
		return n, cw.fail(err)
	}
	cw.hash.Write(data)
	return n, nil
}

func (cw *Writer) Close() error {
	if cw.err != nil {
		return cw.err
	}
	err := cw.file.Close()
	if err != nil {
		return cw.fail(err)
	}
	sum := cw.hash.Sum(nil)
	digest := hex.EncodeToString(sum[:])
	if cw.digest == "" {
		cw.digest = digest
	} else if digest != cw.digest {
		return cw.fail(fmt.Errorf("expected digest %s, got %s", cw.digest, digest))
	}
	fname := cw.file.Name()
	err = os.Rename(fname, filepath.Join(filepath.Dir(fname), cw.digest))
	if err != nil {
		return cw.fail(err)
	}
	cw.err = io.EOF
	return nil
}

func (cw *Writer) Digest() string {
	return cw.digest
}

var MissErr = fmt.Errorf("not cached")

func (c *Cache) filePathAlgo(algo HashAlgorithm, digest string) string {
	return filepath.Join(c.Dir, string(algo), digest)
}

func (c *Cache) Create(digest string) *Writer {
	return c.CreateWithAlgo(SHA256, digest)
}

func (c *Cache) CreateWithAlgo(algo HashAlgorithm, digest string) *Writer {
	if c.Dir == "" {
		return &Writer{err: fmt.Errorf("internal error: cache directory is unset")}
	}
	h, err := newHash(algo)
	if err != nil {
		return &Writer{err: err}
	}
	err = os.MkdirAll(filepath.Join(c.Dir, string(algo)), 0o755)
	if err != nil {
		return &Writer{err: fmt.Errorf("cannot create cache directory: %v", err)}
	}
	var file *os.File
	if digest == "" {
		file, err = os.CreateTemp(c.filePathAlgo(algo, ""), "tmp.*")
	} else {
		file, err = os.Create(c.filePathAlgo(algo, digest+".tmp"))
	}
	if err != nil {
		return &Writer{err: fmt.Errorf("cannot create cache file: %v", err)}
	}
	return &Writer{
		dir:    c.Dir,
		algo:   algo,
		digest: digest,
		hash:   h,
		file:   file,
	}
}

func (c *Cache) Write(digest string, data []byte) error {
	return c.WriteWithAlgo(SHA256, digest, data)
}

func (c *Cache) WriteWithAlgo(algo HashAlgorithm, digest string, data []byte) error {
	f := c.CreateWithAlgo(algo, digest)
	_, err1 := f.Write(data)
	err2 := f.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (c *Cache) Open(digest string) (io.ReadSeekCloser, error) {
	return c.OpenWithAlgo(SHA256, digest)
}

func (c *Cache) OpenWithAlgo(algo HashAlgorithm, digest string) (io.ReadSeekCloser, error) {
	if c.Dir == "" || digest == "" {
		return nil, MissErr
	}
	filePath := c.filePathAlgo(algo, digest)
	file, err := os.Open(filePath)
	if os.IsNotExist(err) {
		return nil, MissErr
	} else if err != nil {
		return nil, fmt.Errorf("cannot open cache file: %v", err)
	}
	// Use mtime as last reuse time.
	now := time.Now()
	if err := os.Chtimes(filePath, now, now); err != nil {
		return nil, fmt.Errorf("cannot update cached file timestamp: %v", err)
	}
	return file, nil
}

func (c *Cache) Read(digest string) ([]byte, error) {
	return c.ReadWithAlgo(SHA256, digest)
}

func (c *Cache) ReadWithAlgo(algo HashAlgorithm, digest string) ([]byte, error) {
	file, err := c.OpenWithAlgo(algo, digest)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("cannot read file from cache: %v", err)
	}
	return data, nil
}

func (c *Cache) Expire(timeout time.Duration) error {
	algos := []HashAlgorithm{SHA256, SHA3384}
	for _, algo := range algos {
		err := c.expireAlgo(algo, timeout)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Cache) expireAlgo(algo HashAlgorithm, timeout time.Duration) error {
	dir := filepath.Join(c.Dir, string(algo))
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot list cache directory: %v", err)
	}
	expired := time.Now().Add(-timeout)
	for _, entry := range entries {
		finfo, err := entry.Info()
		if err != nil {
			return err
		}
		if finfo.ModTime().After(expired) {
			continue
		}
		err = os.Remove(filepath.Join(dir, finfo.Name()))
		if err != nil {
			return fmt.Errorf("cannot expire cache entry: %v", err)
		}
	}
	return nil
}
