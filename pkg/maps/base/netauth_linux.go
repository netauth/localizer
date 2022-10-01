package base

import (
	"path/filepath"

	"github.com/the-maldridge/shadow"
)

const (
	PasswdDB = "passwd"
)

// MergePasswd removes all entries above the minimum UID and then adds
// NetAuth entities that were filtered above.
func (b *Base) MergePasswd() {
	b.passwd.Del(b.passwd.FilterUID(func(i int) bool {
		return i >= int(b.minUID)
	}))

	tmp := make([]*shadow.PasswdEntry, len(b.entities))
	idx := 0
	for i := range b.entities {
		e := shadow.PasswdEntry{
			Login:    b.entities[i].GetID(),
			Password: "*",
			UID:      int(b.entities[i].GetNumber()),
			GID:      int(b.pgroups[b.entities[i].GetMeta().GetPrimaryGroup()]),
			Comment:  b.entities[i].GetMeta().GetGECOS(),
			Home:     filepath.Join(b.baseHome, b.entities[i].GetID()),
			Shell:    b.shell(b.entities[i].GetMeta().GetShell()),
		}
		tmp[idx] = &e
		idx++
	}

	b.passwd.Add(tmp)
}
