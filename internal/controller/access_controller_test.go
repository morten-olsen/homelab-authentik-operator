package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authv1 "github.com/mortenolsen/operator-authentik/api/v1alpha1"
	"github.com/mortenolsen/operator-authentik/internal/authentik"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestAccessOptInAndFailureStatus(t *testing.T) {
	missing := []authv1.NamespacedName{{Name: "missing", Namespace: "shared"}}
	empty := []authv1.NamespacedName{}
	for _, tc := range []struct {
		name    string
		refs    *[]authv1.NamespacedName
		sticky  bool
		managed bool
	}{
		{name: "legacy omission preserved"},
		{name: "missing reference closes", refs: &missing, managed: true},
		{name: "explicitly empty closes", refs: &empty, managed: true},
		{name: "omission after opt-in closes", sticky: true, managed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := map[string]any{"pk": "app-1", "slug": "prod-example", "provider": 12, "policy_engine_mode": "any"}
			bindings := []map[string]any{}
			writes := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p := r.URL.Path
				switch {
				case strings.Contains(p, "policies/expression") && r.Method == http.MethodGet:
					_, _ = fmt.Fprint(w, `{"results":[],"pagination":{"next":0}}`)
				case strings.Contains(p, "policies/expression") && r.Method == http.MethodPost:
					writes++
					var policy map[string]any
					checkTestError(t, json.NewDecoder(r.Body).Decode(&policy))
					policy["pk"] = "guard-1"
					checkTestError(t, json.NewEncoder(w).Encode(policy))
				case strings.Contains(p, "core/applications") && r.Method == http.MethodGet:
					checkTestError(t, json.NewEncoder(w).Encode(app))
				case strings.Contains(p, "core/applications") && r.Method == http.MethodPatch:
					writes++
					var patch map[string]any
					checkTestError(t, json.NewDecoder(r.Body).Decode(&patch))
					for k, v := range patch {
						app[k] = v
					}
					checkTestError(t, json.NewEncoder(w).Encode(app))
				case strings.Contains(p, "policies/bindings") && r.Method == http.MethodGet:
					checkTestError(t, json.NewEncoder(w).Encode(map[string]any{"results": bindings, "pagination": map[string]int{"next": 0}}))
				case strings.Contains(p, "policies/bindings") && r.Method == http.MethodPost:
					writes++
					var b map[string]any
					checkTestError(t, json.NewDecoder(r.Body).Decode(&b))
					b["pk"] = "guard-binding"
					bindings = append(bindings, b)
					checkTestError(t, json.NewEncoder(w).Encode(b))
				default:
					t.Errorf("unexpected request %s %s", r.Method, p)
					w.WriteHeader(500)
				}
			}))
			defer srv.Close()
			scheme := runtime.NewScheme()
			checkTestError(t, authv1.AddToScheme(scheme))
			c := &authv1.AuthentikClient{ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "prod", UID: "client-uid", Generation: 2}, Spec: authv1.AuthentikClientSpec{Name: "example", AllowedGroups: tc.refs}, Status: authv1.AuthentikClientStatus{ProviderID: 12, ApplicationID: "prod-example", Ready: true, AccessManaged: tc.sticky}}
			kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(c).WithObjects(c).Build()
			r := &AuthentikClientReconciler{Client: kube, Scheme: scheme}
			managed, err := r.prepareAccess(context.Background(), c, authentik.NewClient(srv.URL, "test-token", false, ""))
			if managed != tc.managed || (err != nil) != tc.managed {
				t.Fatalf("managed=%v err=%v", managed, err)
			}
			if !tc.managed {
				if writes != 0 {
					t.Fatal("legacy application mutated")
				}
				return
			}
			var saved authv1.AuthentikClient
			checkTestError(t, kube.Get(context.Background(), types.NamespacedName{Name: c.Name, Namespace: c.Namespace}, &saved))
			if saved.Status.Ready || !saved.Status.AccessManaged {
				t.Fatalf("unsafe status: %+v", saved.Status)
			}
			if app["provider"] != nil || app["policy_engine_mode"] != "all" || len(bindings) != 1 {
				t.Fatalf("failed application not closed: %+v", app)
			}
		})
	}
}
func TestExplicitEmptyAllowedGroupsSurvivesSerialization(t *testing.T) {
	empty := []authv1.NamespacedName{}
	c := authv1.AuthentikClient{Spec: authv1.AuthentikClientSpec{AllowedGroups: &empty}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var decoded authv1.AuthentikClient
	checkTestError(t, json.Unmarshal(b, &decoded))
	if decoded.Spec.AllowedGroups == nil {
		t.Fatal("an explicit empty deny-list became legacy omission")
	}
}

func checkTestError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("test JSON I/O failed: %v", err)
	}
}
