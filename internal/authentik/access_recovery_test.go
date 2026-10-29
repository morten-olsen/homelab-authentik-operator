package authentik

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A provider can be attached before the final Kubernetes status write conflicts.
// Recovery must close the UID-owned application without adopting the remote
// provider ID, then rebuild the exact access policy before any later attachment.
func TestOwnedApplicationRecoversLostProviderStatus(t *testing.T) {
	for _, missingGroup := range []bool{false, true} {
		t.Run(map[bool]string{false: "recover", true: "missing group stays closed"}[missingGroup], func(t *testing.T) {
			f := &accessFixture{t: t, app: &AccessApplication{PK: "app-1", Slug: "prod-example", Provider: 12, Mode: accessModeAny, Description: applicationOwner("client-uid")}, missing: missingGroup, policies: []GuardPolicy{}, bindings: []AccessBinding{}}
			srv := httptest.NewServer(http.HandlerFunc(f.handler))
			defer srv.Close()
			plan := AccessPlan{Slug: "prod-example", Name: "example", Owner: "client-uid", Groups: []GroupIdentity{{ID: "g1", Name: "gitops/prod/example", Owner: "group-uid", Users: []int32{7}}}}
			_, err := NewClient(srv.URL, "private", false, "").ReconcileAccess(context.Background(), plan)
			if (err != nil) != missingGroup {
				t.Fatalf("status loss recovery: %v", err)
			}
			if f.app.Provider != 0 || !f.closed || f.unsafe || plan.ProviderID != 0 {
				t.Fatalf("recovery adopted a provider or did not close the app: %+v", f)
			}
			if missingGroup && f.app.Mode != accessModeAll {
				t.Fatal("unresolved group did not retain ALL mode")
			}
		})
	}
}

func TestProviderStatusRecoveryRefusesUnclaimedOrConflictingIdentity(t *testing.T) {
	for _, tc := range []struct {
		owner      string
		recordedID int32
	}{{owner: ""}, {owner: applicationOwner("foreign-uid")}, {owner: applicationOwner("client-uid"), recordedID: 99}} {
		f := &accessFixture{t: t, app: &AccessApplication{PK: "foreign", Slug: "prod-example", Provider: 12, Mode: accessModeAny, Description: tc.owner}}
		srv := httptest.NewServer(http.HandlerFunc(f.handler))
		_, err := NewClient(srv.URL, "private", false, "").ReconcileAccess(context.Background(), AccessPlan{Slug: "prod-example", Owner: "client-uid", ProviderID: tc.recordedID})
		srv.Close()
		if err == nil || f.writes != 0 {
			t.Fatal("lost status permitted a foreign application mutation")
		}
	}
}

func TestLostProviderStatusRestartsAfterPartialRecovery(t *testing.T) {
	for fault := 1; fault <= 20; fault++ {
		t.Run(fmt.Sprint(fault), func(t *testing.T) {
			f := &accessFixture{t: t, app: &AccessApplication{PK: "app-1", Slug: "prod-example", Provider: 12, Mode: accessModeAny, Description: applicationOwner("client-uid")}, policies: []GuardPolicy{}, bindings: []AccessBinding{}, failAt: fault}
			srv := httptest.NewServer(http.HandlerFunc(f.handler))
			defer srv.Close()
			plan := AccessPlan{Slug: "prod-example", Owner: "client-uid", Groups: []GroupIdentity{{ID: "g1", Name: "gitops/prod/example", Owner: "group-uid", Users: []int32{7}}}}
			_, _ = NewClient(srv.URL, "private", false, "").ReconcileAccess(context.Background(), plan)
			f.failAt = 0
			_, err := NewClient(srv.URL, "private", false, "").ReconcileAccess(context.Background(), plan)
			if err != nil || f.app.Provider != 0 || f.unsafe {
				t.Fatalf("partial recovery could not restart safely: %v", err)
			}
		})
	}
}

func TestLostProviderStatusRequiresPersistedClosure(t *testing.T) {
	f := &accessFixture{t: t, app: &AccessApplication{PK: "app-1", Slug: "prod-example", Provider: 12, Mode: accessModeAny, Description: applicationOwner("client-uid")}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			w.WriteHeader(200) // acknowledge without persisting the disconnection
			return
		}
		f.handler(w, r)
	}))
	defer srv.Close()
	_, err := NewClient(srv.URL, "private", false, "").ReconcileAccess(context.Background(), AccessPlan{Slug: "prod-example", Owner: "client-uid"})
	if err == nil {
		t.Fatal("recovery continued without verified provider disconnection")
	}
}
