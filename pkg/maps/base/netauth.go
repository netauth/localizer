package base

import (
	"context"
	"path/filepath"

	"github.com/netauth/netauth/pkg/netauth"
	"github.com/the-maldridge/shadow"
)

// ConnectNetAuth establishes the connection from the localizer to the
// NetAuth server.
func (b *Base) ConnectNetAuth() error {
	c, err := netauth.New()
	if err != nil {
		b.Error("Error during client initialization", "error", err)
		return err
	}
	c.SetServiceName("nsscache")
	b.c = c
	return nil
}

// LoadNetAuthData retrieves updated information from a remove NetAuth
// server to be merged into the local data already present.
func (b *Base) LoadNetAuthData(ctx context.Context) error {
	if err := b.findGroups(ctx); err != nil {
		return err
	}
	if err := b.findEntities(ctx); err != nil {
		return err
	}
	if err := b.findMembers(ctx); err != nil {
		return err
	}
	return nil
}

// findGroups fetches a list of groups from the server and discards
// groups with a GID below the specified minimum.  The groups are
// indexed by name targeting both the group struct and the number.
func (b *Base) findGroups(ctx context.Context) error {
	grps, err := b.c.GroupSearch(ctx, "*")
	if err != nil {
		return err
	}
	for i := range grps {
		if grps[i].GetNumber() < b.minGID {
			// Group number is too low, continue without
			// this one.
			b.Warn("Ignoring group, GID is below cutoff",
				"group", grps[i].GetName(),
				"limit", b.minGID,
				"gid", grps[i].GetNumber())
			continue
		}
		b.groups[grps[i].GetName()] = grps[i]
		b.pgroups[grps[i].GetName()] = uint32(grps[i].GetNumber())
	}
	return nil
}

// findEntities fetches a list of entities from the server and
// discards entities with a UID below the specicified minimum or with
// an invalid primary group.  Then, the default shell is checked
// against the shells on the system and optionally replaced with the
// fallback.
func (b *Base) findEntities(ctx context.Context) error {
	ents, err := b.c.EntitySearch(ctx, "*")
	if err != nil {
		return err
	}

	for i := range ents {
		if ents[i].GetNumber() < b.minUID {
			// The uidNumber was too low, continue without
			// this one.
			b.Warn("Ignoring entity, UID is below cutoff",
				"entity", ents[i].GetID(),
				"limit", b.minUID,
				"uid", ents[i].GetNumber())
			continue
		}
		if _, ok := b.pgroups[ents[i].GetMeta().GetPrimaryGroup()]; !ok {
			// The primary group was invalid, continue
			// without this one.
			b.Warn("Ignoring entity, Primary Group is invalid",
				"entity", ents[i].GetID())
			continue
		}
		if _, ok := b.shellWhitelist[ents[i].GetMeta().GetShell()]; !ok {
			ents[i].Meta.Shell = &b.fallbackShell
		}
		b.entities[ents[i].GetID()] = ents[i]
	}
	return nil
}

// findMembers computes the membership of each group that has a high
// enough GID to be present on the machine.
func (b *Base) findMembers(ctx context.Context) error {
	tmp := make(map[string]map[string]struct{})
	for g := range b.groups {
		tmp[g] = make(map[string]struct{})
		members, err := b.c.GroupMembers(ctx, g)
		if err != nil {
			return err
		}
		for i := range members {
			if _, ok := b.entities[members[i].GetID()]; !ok {
				// This entity has already been
				// discarded for some reason.
				continue
			}
			tmp[g][members[i].GetID()] = struct{}{}
		}
	}

	// Add every entity to its primary group.  This isn't
	// necessarily required by the specification, but it does
	// clear up a lot of really confusing corner cases, and is
	// generally what people expect.
	for i := range b.entities {
		tmp[b.entities[i].GetMeta().GetPrimaryGroup()][b.entities[i].GetID()] = struct{}{}
	}

	for g, mem := range tmp {
		b.members[g] = make([]string, len(tmp[g]))
		idx := 0
		for i := range mem {
			b.members[g][idx] = i
			idx++
		}
	}
	return nil
}

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

// MergeGroup removes all group entries above the minimum GID and then
// adds the NetAuth groups that were filtered above.
func (b *Base) MergeGroup() {
	b.group.Del(b.group.FilterGID(func(i int) bool {
		return i >= int(b.minGID)
	}))

	tmp := make([]*shadow.GroupEntry, len(b.groups))
	idx := 0
	for i := range b.groups {
		g := shadow.GroupEntry{
			Name:     b.groups[i].GetName(),
			Password: "*",
			GID:      int(b.groups[i].GetNumber()),
			UserList: b.members[b.groups[i].GetName()],
		}
		tmp[idx] = &g
		idx++
	}

	b.group.Add(tmp)
}
