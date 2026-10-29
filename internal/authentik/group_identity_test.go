package authentik

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

const identityGroupName = "gitops/prod/identity-test"
const identityGroupOwner = "identity-owner"

type groupIdentityFixture struct {
	t             *testing.T
	groups        map[string]ManagedGroup
	posts, puts   int
	discardWrites bool
}

func ownedIdentityGroup(pk, name string) ManagedGroup {
	return ManagedGroup{PK: pk, Name: name, Users: []int32{99}, Parents: []string{}, Roles: []string{}, Attributes: map[string]any{groupOwnerKey: identityGroupOwner}}
}
func (f *groupIdentityFixture) handler(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/v3/core/users/") {
		_, _ = fmt.Fprint(w, `{"pk":7,"uuid":"person-uuid","is_active":true,"type":"internal"}`)
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v3/core/groups/"), "/")
	switch r.Method {
	case http.MethodGet:
		if id != "" {
			g, ok := f.groups[id]
			if !ok {
				w.WriteHeader(404)
				return
			}
			checkTestError(f.t, json.NewEncoder(w).Encode(g))
			return
		}
		groups := make([]ManagedGroup, 0, len(f.groups))
		keys := make([]string, 0, len(f.groups))
		for key := range f.groups {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			groups = append(groups, f.groups[key])
		}
		checkTestError(f.t, json.NewEncoder(w).Encode(map[string]any{"results": groups, "pagination": map[string]int{"next": 0}}))
	case http.MethodPost, http.MethodPut:
		var group ManagedGroup
		checkTestError(f.t, json.NewDecoder(r.Body).Decode(&group))
		if r.Method == http.MethodPost {
			f.posts++
			id = fmt.Sprintf("created-%d", f.posts)
		} else {
			f.puts++
		}
		group.PK = id
		if !f.discardWrites {
			f.groups[id] = group
		}
		checkTestError(f.t, json.NewEncoder(w).Encode(group))
	default:
		f.t.Errorf("unexpected identity mutation %s", r.Method)
		w.WriteHeader(500)
	}
}
func TestGroupRenameReconcilesStableIdentity(t *testing.T) {
	for _, statusID := range []string{"stable-pk", ""} {
		t.Run("status="+statusID, func(t *testing.T) {
			f := &groupIdentityFixture{t: t, groups: map[string]ManagedGroup{"stable-pk": ownedIdentityGroup("stable-pk", "renamed-in-ui")}}
			srv := httptest.NewServer(http.HandlerFunc(f.handler))
			defer srv.Close()
			id := GroupIdentity{ID: statusID, Name: identityGroupName, Owner: identityGroupOwner}
			group, err := NewClient(srv.URL, "private", false, "").ReconcileGroup(context.Background(), id, []UserReference{{ID: 7, UUID: "person-uuid"}})
			if err != nil {
				t.Fatal(err)
			}
			if group.PK != "stable-pk" || group.Name != identityGroupName || len(f.groups) != 1 || f.posts != 0 {
				t.Fatalf("rename orphaned identity: %+v", f)
			}
			if len(group.Users) != 1 || group.Users[0] != 7 {
				t.Fatalf("membership not reconciled on stable identity: %+v", group)
			}
		})
	}
}
func TestRenamedGroupDeletionRevokesAndVerifies(t *testing.T) {
	for _, statusID := range []string{"stable-pk", ""} {
		t.Run("status="+statusID, func(t *testing.T) {
			group := ownedIdentityGroup("stable-pk", "renamed-in-ui")
			group.IsSuperuser = true
			group.Roles = []string{"drifted-role"}
			// A foreign group now has the desired name. Revocation must still target
			// the owned PK and must not rename or edit the foreign identity.
			foreign := ManagedGroup{PK: "foreign-pk", Name: identityGroupName, Users: []int32{88}}
			f := &groupIdentityFixture{t: t, groups: map[string]ManagedGroup{group.PK: group, foreign.PK: foreign}}
			srv := httptest.NewServer(http.HandlerFunc(f.handler))
			defer srv.Close()
			err := NewClient(srv.URL, "private", false, "").RevokeGroup(context.Background(), GroupIdentity{ID: statusID, Name: identityGroupName, Owner: identityGroupOwner})
			if err != nil {
				t.Fatal(err)
			}
			retained := f.groups[group.PK]
			if len(retained.Users) > 0 || retained.IsSuperuser || len(retained.Roles) > 0 || retained.Name != group.Name || len(f.groups) != 2 || f.posts != 0 {
				t.Fatalf("owned identity not safely retained/revoked: %+v", f)
			}
			if f.groups[foreign.PK].Users[0] != 88 {
				t.Fatal("foreign group modified")
			}
		})
	}
}
func TestGroupIdentityConflictsDoNotCreateOrAdopt(t *testing.T) {
	cases := []struct {
		name, statusID string
		groups         []ManagedGroup
	}{
		{name: "duplicate owner lost status", groups: []ManagedGroup{ownedIdentityGroup("one", "rename-one"), ownedIdentityGroup("two", "rename-two")}},
		{name: "duplicate owner known status", statusID: "one", groups: []ManagedGroup{ownedIdentityGroup("one", identityGroupName), ownedIdentityGroup("two", "rename-two")}},
		{name: "foreign persisted PK", statusID: "foreign", groups: []ManagedGroup{{PK: "foreign", Name: "unmanaged", Users: []int32{88}}, ownedIdentityGroup("owned", identityGroupName)}},
		{name: "foreign desired name", groups: []ManagedGroup{{PK: "foreign", Name: identityGroupName, Users: []int32{88}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &groupIdentityFixture{t: t, groups: map[string]ManagedGroup{}}
			for _, g := range tc.groups {
				f.groups[g.PK] = g
			}
			srv := httptest.NewServer(http.HandlerFunc(f.handler))
			defer srv.Close()
			_, err := NewClient(srv.URL, "private", false, "").ReconcileGroup(context.Background(), GroupIdentity{ID: tc.statusID, Name: identityGroupName, Owner: identityGroupOwner}, nil)
			if err == nil || f.posts != 0 || f.puts != 0 {
				t.Fatalf("conflict not rejected: err=%v writes=%d/%d", err, f.posts, f.puts)
			}
		})
	}
}
func TestDeletionRefusesAmbiguousOwnershipOrUnpersistedRevocation(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		duplicate, foreign, discard bool
	}{
		{name: "duplicate owner", duplicate: true}, {name: "foreign persisted PK", foreign: true}, {name: "write not persisted", discard: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &groupIdentityFixture{t: t, groups: map[string]ManagedGroup{"stable-pk": ownedIdentityGroup("stable-pk", identityGroupName)}, discardWrites: tc.discard}
			if tc.duplicate {
				f.groups["other"] = ownedIdentityGroup("other", "renamed-other")
			}
			if tc.foreign {
				g := f.groups["stable-pk"]
				g.Attributes = map[string]any{}
				f.groups["stable-pk"] = g
			}
			srv := httptest.NewServer(http.HandlerFunc(f.handler))
			defer srv.Close()
			err := NewClient(srv.URL, "private", false, "").RevokeGroup(context.Background(), GroupIdentity{ID: "stable-pk", Name: identityGroupName, Owner: identityGroupOwner})
			if err == nil {
				t.Fatal("unverified revocation would release deletion finalizer")
			}
			if (tc.duplicate || tc.foreign) && (f.posts != 0 || f.puts != 0) {
				t.Fatal("ambiguous/foreign identity mutated")
			}
		})
	}
}
