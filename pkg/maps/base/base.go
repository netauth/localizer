package base

import (
	"bufio"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-hclog"

	"github.com/the-maldridge/shadow"

	pb "github.com/netauth/protocol"
)

// New returns a new initialized Base maps structure.
func New() *Base {
	b := new(Base)
	b.Logger = hclog.L().Named("base-identity")

	b.shellWhitelist = make(map[string]struct{})
	b.entities = make(map[string]*pb.Entity)
	b.groups = make(map[string]*pb.Group)
	b.members = make(map[string][]string)
	b.pgroups = make(map[string]uint32)

	b.passwd = &shadow.PasswdMap{}
	b.group = &shadow.GroupMap{}
	return b
}

// SetBaseDir specifies the base directory that all files are read
// from and written to.
func (b *Base) SetBaseDir(s string) {
	b.baseDir = s
}

// SetBaseHome specifies the base directory that will be prepended to
// all entity IDs to construct the path written to the passwd map.
func (b *Base) SetBaseHome(s string) {
	b.baseHome = s
}

// SetMinUID specifies the minimum UID that should be accepted from
// NetAuth.  UIDs below this value are asserted to be local to the
// system and are not modified.
func (b *Base) SetMinUID(m int32) {
	b.minUID = m
}

// SetMinGID specifies the minimum GID that should be accepted from
// NetAuth.  GIDs below this value are asserted to be local to the
// system and are not modified.
func (b *Base) SetMinGID(m int32) {
	b.minGID = m
}

// SetFallbackShell is used to specify the shell that should be used
// if the requested shell is not present on the system or otherwise is
// not specified.
func (b *Base) SetFallbackShell(s string) {
	b.fallbackShell = s
}

// SetLogger sets the internal logger used by the module.  If
// unspecified logging is enabled on the default logger.
func (b *Base) SetLogger(l hclog.Logger) {
	b.Logger = l
}

// loadShells loads the contents of the `shells` file which
// canonically holds the allowed user command interpreters.  This file
// is then treated as a whitelist and entities that do not have a
// shell that matches an entry in this filter are patched according
// the fallback shell specified above.
func (b *Base) loadShells() error {
	f, err := os.Open(filepath.Join(b.baseDir, "shells"))
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		b.shellWhitelist[scanner.Text()] = struct{}{}
	}
	return nil
}

// loadPasswd loads the passwd map from disk and parses it for
// manipulation.  No filtering is done on load, all filtering is
// handled during patching.
func (b *Base) loadPasswd() error {
	pf, err := os.Open(filepath.Join(b.baseDir, "passwd"))
	if err != nil {
		return err
	}
	defer pf.Close()

	b.passwd, err = shadow.ParsePasswdMap(pf)
	if err != nil {
		return err
	}
	return nil
}

// loadGroup fills the same function as the loadPasswd function above,
// but for the group map.
func (b *Base) loadGroup() error {
	gf, err := os.Open(filepath.Join(b.baseDir, "group"))
	if err != nil {
		return err
	}
	defer gf.Close()

	b.group, err = shadow.ParseGroupMap(gf)
	if err != nil {
		return err
	}
	return nil
}

// Load loads the passwd and shadow maps into the Base struct.
func (b *Base) Load() error {
	if err := b.loadShells(); err != nil {
		return err
	}

	if err := b.loadPasswd(); err != nil {
		return err
	}

	if err := b.loadGroup(); err != nil {
		return err
	}

	return nil
}
