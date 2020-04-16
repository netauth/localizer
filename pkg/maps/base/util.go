package base

import (
	"github.com/the-maldridge/shadow"
)

// shell checks the provided shell against the whitelist and either
// returns it or returns the fallback shell if the requested shell is
// not present in the whitelist.
func (b *Base) shell(s string) string {
	if _, ok := b.shellWhitelist[s]; !ok {
		return b.fallbackShell
	}
	return s
}

// FetchPasswd returns the passwd map as a formatted string suitable
// for passing into another map module.
func (b *Base) FetchPasswd() shadow.PasswdMap {
	return *b.passwd
}

// FetchGroup returns the group map as a formatted string suitable for
// passing into another map module.
func (b *Base) FetchGroup() shadow.GroupMap {
	return *b.group
}

// PasswdBytes returns a byte representation of the new passwd file as
// it should appear for writing to disk.
func (b *Base) PasswdBytes() []byte {
	return []byte(b.passwd.String())
}

// GroupBytes returns a byte representation of the new group file as
// it should appear for writing to disk.
func (b *Base) GroupBytes() []byte {
	return []byte(b.group.String())
}
