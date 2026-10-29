package authentik

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Exercise the public reconciliation seam against a real HTTP adapter. The fake
// records every state visible to an authorization request between API writes.
func TestGroupOwnershipAndMembership(t *testing.T) {
	for _, tc := range []struct {
		name          string
		existingOwner string
		missing       bool
		wantErr       bool
	}{
		{"create", "", false, false}, {"owned", "uid-1", false, false},
		{"name collision", "someone-else", false, true}, {"missing user revokes", "uid-1", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var group *ManagedGroup
			if tc.existingOwner != "" {
				group = &ManagedGroup{PK: "g1", Name: "gitops/shared/admin", Attributes: map[string]any{groupOwnerKey: tc.existingOwner}, Users: []int32{99}}
			}
			writes := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/v3/core/users/"):
					if tc.missing {
						w.WriteHeader(404)
						return
					}
					fmt.Fprint(w, `{"pk":7,"uuid":"person-uuid","is_active":true,"type":"internal"}`)
				case r.Method == "GET":
					gs := []ManagedGroup{}
					if group != nil {
						gs = append(gs, *group)
					}
					json.NewEncoder(w).Encode(map[string]any{"results": gs, "pagination": map[string]int{"next": 0}})
				default:
					writes++
					var payload map[string]any
					json.NewDecoder(r.Body).Decode(&payload)
					if _, ok := payload["users"]; !ok {
						t.Error("users must be serialized even when empty")
					}
					b, _ := json.Marshal(payload)
					var g ManagedGroup
					json.Unmarshal(b, &g)
					g.PK = "g1"
					group = &g
					json.NewEncoder(w).Encode(g)
				}
			}))
			defer srv.Close()
			c := NewClient(srv.URL, "private-token", false, "")
			_, err := c.ReconcileGroup(context.Background(), GroupIdentity{Name: "gitops/shared/admin", Owner: "uid-1"}, []UserReference{{ID: 7, UUID: "person-uuid"}})
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v", err)
			}
			if tc.existingOwner == "someone-else" && writes != 0 {
				t.Fatal("adopted a foreign group")
			}
			if tc.missing && len(group.Users) != 0 {
				t.Fatal("stale membership survived an invalid user reference")
			}
			if !tc.wantErr && (len(group.Users) != 1 || group.Users[0] != 7 || group.IsSuperuser || len(group.Roles) > 0) {
				t.Fatalf("unexpected group: %+v", group)
			}
		})
	}
}

func TestAccessGuardedCutover(t *testing.T) {
	for _, tc := range []struct {
		name       string
		missing    bool
		failCreate bool
		approveOld bool
		wantErr    bool
	}{
		{name: "replace allow all", approveOld: true},
		{name: "unapproved binding", wantErr: true},
		{name: "missing group", missing: true, approveOld: true, wantErr: true},
		{name: "partial binding failure", failCreate: true, approveOld: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := AccessApplication{PK: "app-1", Slug: "prod-example", Provider: 12, Mode: "any"}
			bindings := []AccessBinding{{PK: "old-allow-all", Target: app.PK, Policy: "old-policy", Enabled: true}}
			policy := GuardPolicy{PK: "guard-1", Name: "gitops/client/client-uid", Expression: guardExpression("client-uid")}
			closed := false
			sawClosed := false
			violations := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p := r.URL.Path
				switch {
				case strings.Contains(p, "policies/expression"):
					json.NewEncoder(w).Encode(map[string]any{"results": []GuardPolicy{policy}, "pagination": map[string]int{"next": 0}})
				case strings.Contains(p, "core/groups"):
					if tc.missing {
						w.WriteHeader(404)
						return
					}
					g := ManagedGroup{PK: "g1", Name: "gitops/prod/example", Attributes: map[string]any{groupOwnerKey: "group-uid"}, Users: []int32{7}}
					if p == "/api/v3/core/groups/" {
						json.NewEncoder(w).Encode(map[string]any{"results": []ManagedGroup{g}, "pagination": map[string]int{"next": 0}})
					} else {
						json.NewEncoder(w).Encode(g)
					}
				case p == "/api/v3/core/applications/prod-example/" && r.Method == "GET":
					json.NewEncoder(w).Encode(app)
				case strings.Contains(p, "core/applications") && r.Method == "PATCH":
					var v map[string]any
					json.NewDecoder(r.Body).Decode(&v)
					if m, ok := v["policy_engine_mode"].(string); ok {
						app.Mode = m
					}
					json.NewEncoder(w).Encode(app)
				case strings.Contains(p, "policies/bindings") && r.Method == "GET":
					json.NewEncoder(w).Encode(map[string]any{"results": bindings, "pagination": map[string]int{"next": 0}})
				case strings.Contains(p, "policies/bindings") && r.Method == "POST":
					var b AccessBinding
					json.NewDecoder(r.Body).Decode(&b)
					if b.Group != "" && tc.failCreate {
						w.WriteHeader(500)
						return
					}
					b.PK = fmt.Sprintf("b%d", len(bindings))
					bindings = append(bindings, b)
					json.NewEncoder(w).Encode(b)
				case strings.Contains(p, "policies/bindings") && r.Method == "DELETE":
					id := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v3/policies/bindings/"), "/")
					for i, b := range bindings {
						if b.PK == id {
							bindings = append(bindings[:i], bindings[i+1:]...)
							break
						}
					}
					w.WriteHeader(204)
				default:
					t.Errorf("unexpected request %s %s", r.Method, p)
					w.WriteHeader(500)
				}
				guard := false
				old := false
				grant := false
				for _, b := range bindings {
					guard = guard || b.Policy == "guard-1"
					old = old || b.PK == "old-allow-all"
					grant = grant || b.Group == "g1"
				}
				closed = app.Mode == "all" && guard
				if closed {
					sawClosed = true
				}
				if sawClosed && !closed && (old || !guard || !grant || tc.wantErr) {
					violations++
				}
			}))
			defer srv.Close()
			plan := AccessPlan{Slug: app.Slug, Name: "example", Owner: "client-uid", ProviderID: 12, ClaimExisting: true, Groups: []GroupIdentity{{ID: "g1", Name: "gitops/prod/example", Owner: "group-uid", Users: []int32{7}}}}
			if tc.approveOld {
				plan.ReplacesBindings = []string{"old-allow-all"}
			}
			_, err := NewClient(srv.URL, "private-token", false, "").ReconcileAccess(context.Background(), plan)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v", err)
			}
			if !sawClosed || violations > 0 {
				t.Fatalf("unsafe intermediate state: closed=%v violations=%d", sawClosed, violations)
			}
			if tc.wantErr && !closed {
				t.Fatal("error did not leave application closed")
			}
			if !tc.wantErr && app.Mode != "any" {
				t.Fatal("successful cutover not ANY")
			}
		})
	}
}

// The fake keeps application state across new Client instances, representing
// operator restarts. Faults are injected at every API call in a cutover.
type accessFixture struct {
	app                      *AccessApplication
	policies                 []GuardPolicy
	bindings                 []AccessBinding
	requests, writes, failAt int
	closed                   bool
	unsafe                   bool
	serial                   int
}

func (f *accessFixture) handler(w http.ResponseWriter, r *http.Request) {
	f.requests++
	if f.requests == f.failAt {
		w.WriteHeader(503)
		return
	}
	if r.Method != "GET" {
		f.writes++
	}
	p := r.URL.Path
	switch {
	case p == "/api/v3/core/groups/":
		json.NewEncoder(w).Encode(map[string]any{"results": []ManagedGroup{}, "pagination": map[string]int{"next": 0}})
	case strings.HasPrefix(p, "/api/v3/core/groups/"):
		json.NewEncoder(w).Encode(ManagedGroup{PK: "g1", Name: "gitops/prod/example", Users: []int32{7}, Attributes: map[string]any{groupOwnerKey: "group-uid"}})
	case p == "/api/v3/policies/expression/" && r.Method == "GET":
		json.NewEncoder(w).Encode(map[string]any{"results": f.policies, "pagination": map[string]int{"next": 0}})
	case p == "/api/v3/policies/expression/" && r.Method == "POST":
		var policy GuardPolicy
		json.NewDecoder(r.Body).Decode(&policy)
		policy.PK = "guard-1"
		f.policies = append(f.policies, policy)
		json.NewEncoder(w).Encode(policy)
	case strings.HasPrefix(p, "/api/v3/core/applications/") && r.Method == "GET":
		if f.app == nil {
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(f.app)
	case p == "/api/v3/core/applications/" && r.Method == "POST":
		f.app = &AccessApplication{}
		json.NewDecoder(r.Body).Decode(f.app)
		f.app.PK = "app-1"
		json.NewEncoder(w).Encode(f.app)
	case strings.HasPrefix(p, "/api/v3/core/applications/") && r.Method == "PATCH":
		var patch map[string]json.RawMessage
		json.NewDecoder(r.Body).Decode(&patch)
		if v, ok := patch["policy_engine_mode"]; ok {
			json.Unmarshal(v, &f.app.Mode)
		}
		if v, ok := patch["meta_description"]; ok {
			json.Unmarshal(v, &f.app.Description)
		}
		if v, ok := patch["provider"]; ok {
			f.app.Provider = 0
			json.Unmarshal(v, &f.app.Provider)
		}
		json.NewEncoder(w).Encode(f.app)
	case p == "/api/v3/policies/bindings/" && r.Method == "GET":
		json.NewEncoder(w).Encode(map[string]any{"results": f.bindings, "pagination": map[string]int{"next": 0}})
	case p == "/api/v3/policies/bindings/" && r.Method == "POST":
		var b AccessBinding
		json.NewDecoder(r.Body).Decode(&b)
		f.serial++
		b.PK = fmt.Sprintf("binding-%d", f.serial)
		f.bindings = append(f.bindings, b)
		json.NewEncoder(w).Encode(b)
	case strings.HasPrefix(p, "/api/v3/policies/bindings/") && r.Method == "DELETE":
		id := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v3/policies/bindings/"), "/")
		for i, b := range f.bindings {
			if b.PK == id {
				f.bindings = append(f.bindings[:i], f.bindings[i+1:]...)
				break
			}
		}
		w.WriteHeader(204)
	default:
		w.WriteHeader(500)
	}
	if f.app != nil {
		guard, old := false, false
		for _, b := range f.bindings {
			guard = guard || b.Policy == "guard-1"
			old = old || b.Policy == "old-policy"
		}
		nowClosed := f.app.Provider == 0 || (f.app.Mode == "all" && guard)
		if f.closed && !nowClosed && (old || !guard || len(f.bindings) < 2) {
			f.unsafe = true
		}
		f.closed = f.closed || nowClosed
	}
}
func TestRestartAfterEveryPartialAccessFailure(t *testing.T) {
	for _, newApp := range []bool{false, true} {
		for fault := 0; fault <= 18; fault++ {
			t.Run(fmt.Sprintf("new=%v/fault=%d", newApp, fault), func(t *testing.T) {
				f := &accessFixture{policies: []GuardPolicy{}, bindings: []AccessBinding{}, failAt: fault}
				if !newApp {
					f.app = &AccessApplication{PK: "app-1", Slug: "prod-example", Provider: 12, Mode: "any"}
					f.bindings = []AccessBinding{{PK: "legacy", Target: "app-1", Policy: "old-policy", Enabled: true}}
				}
				srv := httptest.NewServer(http.HandlerFunc(f.handler))
				defer srv.Close()
				plan := AccessPlan{Slug: "prod-example", Name: "example", Owner: "client-uid", ProviderID: 12, ClaimExisting: !newApp, ReplacesBindings: []string{"legacy"}, Groups: []GroupIdentity{{ID: "g1", Name: "gitops/prod/example", Owner: "group-uid", Users: []int32{7}}}}
				_, _ = NewClient(srv.URL, "private", false, "").ReconcileAccess(context.Background(), plan)
				f.failAt = 0
				c := NewClient(srv.URL, "private", false, "")
				if _, err := c.ReconcileAccess(context.Background(), plan); err != nil {
					t.Fatalf("restart could not recover: %v", err)
				}
				if err := c.ConnectApplication(context.Background(), plan.Slug, plan.Name, plan.ProviderID); err != nil {
					t.Fatal(err)
				}
				before := f.writes
				if _, err := NewClient(srv.URL, "private", false, "").ReconcileAccess(context.Background(), plan); err != nil {
					t.Fatal(err)
				}
				if f.writes != before {
					t.Fatal("stable reconciliation wrote Authentik state")
				}
				if f.unsafe || f.app.Provider != 12 || f.app.Mode != "any" || len(f.bindings) != 2 {
					t.Fatalf("unsafe final or intermediate state: %+v", f)
				}
			})
		}
	}
}
func TestIdentityChecksAndErrorRedaction(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"id reuse", `{"pk":7,"uuid":"new-person","is_active":true,"type":"internal"}`, 200},
		{"inactive", `{"pk":7,"uuid":"person","is_active":false,"type":"internal"}`, 200},
		{"service account", `{"pk":7,"uuid":"person","is_active":true,"type":"service_account"}`, 200},
		{"server error", `{"secret":"never-log-this"}`, 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) }))
			defer srv.Close()
			_, err := NewClient(srv.URL, "token-never-log", false, "").ResolveMembers(context.Background(), []UserReference{{ID: 7, UUID: "person"}})
			if err == nil {
				t.Fatal("invalid reference accepted")
			}
			if strings.Contains(err.Error(), "never-log") {
				t.Fatalf("sensitive error: %s", err)
			}
		})
	}
}

func TestGroupDeletionRevokesAndRetainsIdentity(t *testing.T) {
	for _, owner := range []string{"", "group-uid", "foreign-uid"} {
		t.Run("owner="+owner, func(t *testing.T) {
			writes := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					groups := []ManagedGroup{}
					if owner != "" {
						groups = append(groups, ManagedGroup{PK: "g1", Name: "gitops/prod/example", Users: []int32{7}, Attributes: map[string]any{groupOwnerKey: owner}})
					}
					json.NewEncoder(w).Encode(map[string]any{"results": groups, "pagination": map[string]int{"next": 0}})
					return
				}
				writes++
				if r.Method != "PUT" || r.URL.Path != "/api/v3/core/groups/g1/" {
					t.Errorf("identity was created or deleted: %s %s", r.Method, r.URL.Path)
				}
				var group ManagedGroup
				json.NewDecoder(r.Body).Decode(&group)
				if len(group.Users) != 0 || group.IsSuperuser || len(group.Roles) > 0 || len(group.Parents) > 0 {
					t.Errorf("not revoked: %+v", group)
				}
				json.NewEncoder(w).Encode(group)
			}))
			defer srv.Close()
			err := NewClient(srv.URL, "private", false, "").RevokeGroup(context.Background(), GroupIdentity{Name: "gitops/prod/example", Owner: "group-uid"})
			if (err != nil) != (owner == "foreign-uid") {
				t.Fatalf("error=%v", err)
			}
			expected := 0
			if owner == "group-uid" {
				expected = 1
			}
			if writes != expected {
				t.Fatalf("writes=%d expected=%d", writes, expected)
			}
		})
	}
}

func TestManagedGroupRejectsPrivilegeAndHierarchyDrift(t *testing.T) {
	for _, kind := range []string{"superuser", "role", "parent", "child", "membership", "owner"} {
		t.Run(kind, func(t *testing.T) {
			group := ManagedGroup{PK: "g1", Name: "gitops/prod/example", Users: []int32{7}, Attributes: map[string]any{groupOwnerKey: "group-uid"}}
			groups := []ManagedGroup{}
			switch kind {
			case "superuser":
				group.IsSuperuser = true
			case "role":
				group.Roles = []string{"privileged"}
			case "parent":
				group.Parents = []string{"parent"}
			case "child":
				groups = append(groups, ManagedGroup{PK: "unmanaged-child", Parents: []string{"g1"}})
			case "membership":
				group.Users = []int32{99}
			case "owner":
				group.Attributes[groupOwnerKey] = "foreign"
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Fatal("validation mutated identity")
				}
				if strings.HasSuffix(r.URL.Path, "/g1/") {
					json.NewEncoder(w).Encode(group)
				} else {
					json.NewEncoder(w).Encode(map[string]any{"results": groups, "pagination": map[string]int{"next": 0}})
				}
			}))
			defer srv.Close()
			if err := NewClient(srv.URL, "private", false, "").ValidateGroup(context.Background(), GroupIdentity{ID: "g1", Name: group.Name, Owner: "group-uid", Users: []int32{7}}); err == nil {
				t.Fatal("unsafe group accepted")
			}
		})
	}
}
