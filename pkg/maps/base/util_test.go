package base

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShell(t *testing.T) {
	b := New()

	b.shellWhitelist["good"] = struct{}{}
	b.fallbackShell = "fallback"

	assert.Equal(t, b.shell("good"), "good")
	assert.NotEqual(t, b.shell("bad"), "bad")
	assert.Equal(t, b.shell("bad"), "fallback")
}

func TestFetchPasswd(t *testing.T) {
	b := New()
	assert.Equal(t, b.FetchPasswd(), *b.passwd)
}

func TestFetchGroup(t *testing.T) {
	b := New()
	assert.Equal(t, b.FetchGroup(), *b.group)
}
