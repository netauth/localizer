package base

import (
	"path/filepath"
	"testing"

	"github.com/Flaque/filet"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
)

func TestSetBaseDir(t *testing.T) {
	b := New()
	b.SetBaseDir("/somewhere")
	assert.Equal(t, b.baseDir, "/somewhere")
}

func TestSetMinUID(t *testing.T) {
	b := New()
	b.SetMinUID(2000)
	assert.Equal(t, b.minUID, int32(2000))
}

func TestSetMinGID(t *testing.T) {
	b := New()
	b.SetMinGID(2000)
	assert.Equal(t, b.minGID, int32(2000))
}

func TestSetFallbackShell(t *testing.T) {
	b := New()
	b.SetFallbackShell("/bin/nologin")
	assert.Equal(t, b.fallbackShell, "/bin/nologin")
}

func TestSetLogger(t *testing.T) {
	b := New()
	l := hclog.New(nil)
	b.SetLogger(l)
	assert.Equal(t, b.Logger, l)
}

func TestLoadShells(t *testing.T) {
	defer filet.CleanUp(t)
	d := filet.TmpDir(t, "")
	b := New()
	b.SetBaseDir(d)

	assert.NotNil(t, b.loadShells(), "Loaded shells from empty base?")

	filet.File(t, filepath.Join(d, "shells"), "/bin/bash\n/bin/sh\n")
	assert.Nil(t, b.loadShells(), "Failure to load shells whitelist")
}

func TestLoadPasswd(t *testing.T) {
	defer filet.CleanUp(t)
	d := filet.TmpDir(t, "")
	b := New()
	b.SetBaseDir(d)

	assert.NotNil(t, b.loadPasswd(), "Loaded passwd from empty base?")

	filet.File(t, filepath.Join(d, "passwd"), "asdf")
	assert.NotNil(t, b.loadPasswd(), "Loaded corrupt file with no error?")

	filet.File(t, filepath.Join(d, "passwd"), "dnsmasq:x:988:984:dnsmasq unprivileged user:/var/chroot:/sbin/nologin")
	assert.Nil(t, b.loadPasswd(), "Failed to load file.")
}

func TestLoadGroup(t *testing.T) {
	defer filet.CleanUp(t)
	d := filet.TmpDir(t, "")
	b := New()
	b.SetBaseDir(d)

	assert.NotNil(t, b.loadGroup(), "Loaded group from empty base?")

	filet.File(t, filepath.Join(d, "group"), "asdf")
	assert.NotNil(t, b.loadGroup(), "Loaded corrupt file with no error?")

	filet.File(t, filepath.Join(d, "group"), "rsvlog:x:990:\nkvm:x:24:libvirt,maldridge\n")
	assert.Nil(t, b.loadGroup(), "Failed to load file.")
}

func TestLoad(t *testing.T) {
	defer filet.CleanUp(t)
	d := filet.TmpDir(t, "")
	b := New()
	b.SetBaseDir(d)

	assert.NotNil(t, b.Load(), "Loaded with no shells?")

	filet.File(t, filepath.Join(d, "shells"), "/bin/bash\n/bin/sh\n")
	assert.NotNil(t, b.Load(), "Loaded with no passwd?")

	filet.File(t, filepath.Join(d, "passwd"), "root:x:0:0:root:/root:/bin/sh\n")
	assert.NotNil(t, b.Load(), "Loaded with no group?")

	filet.File(t, filepath.Join(d, "group"), "rsvlog:x:990:\nkvm:x:24:libvirt,maldridge\n")
	assert.Nil(t, b.Load(), "Failed to load with OK basedir")
}
