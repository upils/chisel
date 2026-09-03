package store_test

import (
	"testing"

	"github.com/canonical/chisel/internal/store"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type S struct{}

var _ = Suite(&S{})

func (s *S) SetUpTest(c *C) {
	store.SetDebug(true)
	store.SetLogger(c)
}

func (s *S) TearDownTest(c *C) {
	store.SetDebug(false)
	store.SetLogger(nil)
}
