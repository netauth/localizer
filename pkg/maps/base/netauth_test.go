package base

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"github.com/the-maldridge/shadow"

	pb "github.com/netauth/protocol"
)

func TestMergePasswd(t *testing.T) {
	b := New()

	b.passwd.Add([]*shadow.PasswdEntry{
		{
			Login:    "test1",
			Password: "*",
			UID:      100,
			GID:      100,
			Comment:  "",
			Home:     "/home/test1",
			Shell:    "/bin/sh",
		},
		{
			Login:    "test2",
			Password: "*",
			UID:      200,
			GID:      100,
			Comment:  "",
			Home:     "/home/test2",
			Shell:    "/bin/sh",
		},
	})
	b.minUID = 150
	b.entities = map[string]*pb.Entity{
		"test2": {
			ID:     proto.String("test3"),
			Number: proto.Int32(300),
			Meta: &pb.EntityMeta{
				PrimaryGroup: proto.String("pgroup1"),
				Shell:        proto.String("/bin/sh"),
			},
		},
	}

	b.MergePasswd()

	assert.Contains(t, b.passwd.String(), "test3")
	assert.NotContains(t, b.passwd.String(), "test2")
}

func TestMergeGroup(t *testing.T) {
	b := New()

	b.group.Add([]*shadow.GroupEntry{
		{
			Name:     "group1",
			Password: "*",
			GID:      100,
			UserList: []string{},
		},
		{
			Name:     "group2",
			Password: "*",
			GID:      200,
			UserList: []string{},
		},
	})
	b.minGID = 150
	b.groups = map[string]*pb.Group{
		"group3": {
			Name:   proto.String("group3"),
			Number: proto.Int32(300),
		},
	}

	b.MergeGroup()

	assert.Contains(t, b.group.String(), "group3")
	assert.NotContains(t, b.group.String(), "group2")
}
