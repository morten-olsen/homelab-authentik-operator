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

// A proxy provider without a usable allowed group must never reach the outpost:
// the application stays disconnected in ALL mode and no provider is created.
func TestProxyProviderAccessFailureNeverAttaches(t *testing.T) {
	missing := []authv1.NamespacedName{{Name: "missing", Namespace: "shared"}}
	for _, tc := range []struct {
		name string
		refs []authv1.NamespacedName
	}{
		{name: "omitted denies"},
		{name: "missing group denies", refs: missing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := map[string]any{}
			bindings := []map[string]any{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p := r.URL.Path
				switch {
				case strings.Contains(p, "policies/expression") && r.Method == http.MethodGet:
					_, _ = fmt.Fprint(w, `{"results":[],"pagination":{"next":0}}`)
				case strings.Contains(p, "policies/expression") && r.Method == http.MethodPost:
					var policy map[string]any
					checkTestError(t, json.NewDecoder(r.Body).Decode(&policy))
					policy["pk"] = "guard-1"
					checkTestError(t, json.NewEncoder(w).Encode(policy))
				case strings.Contains(p, "core/applications") && r.Method == http.MethodGet:
					if len(app) == 0 {
						w.WriteHeader(404)
						return
					}
					checkTestError(t, json.NewEncoder(w).Encode(app))
				case strings.Contains(p, "core/applications") && (r.Method == http.MethodPost || r.Method == http.MethodPatch):
					var patch map[string]any
					checkTestError(t, json.NewDecoder(r.Body).Decode(&patch))
					for k, v := range patch {
						app[k] = v
					}
					app["pk"] = "app-1"
					checkTestError(t, json.NewEncoder(w).Encode(app))
				case strings.Contains(p, "policies/bindings") && r.Method == http.MethodGet:
					checkTestError(t, json.NewEncoder(w).Encode(map[string]any{"results": bindings, "pagination": map[string]int{"next": 0}}))
				case strings.Contains(p, "policies/bindings") && r.Method == http.MethodPost:
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
			ref := authv1.NamespacedName{Name: "authentik", Namespace: "shared"}
			p := &authv1.AuthentikProxyProvider{ObjectMeta: metav1.ObjectMeta{Name: "whoami", Namespace: "prod", UID: "proxy-uid", Generation: 1}, Spec: authv1.AuthentikProxyProviderSpec{ServerRef: ref, Name: "whoami", ExternalHost: "https://whoami.example.com", AllowedGroups: tc.refs}}
			server := &authv1.AuthentikServer{ObjectMeta: metav1.ObjectMeta{Name: "authentik", Namespace: "shared"}, Spec: authv1.AuthentikServerSpec{Host: "auth.example.com"}}
			kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(p).WithObjects(p, server).Build()
			r := &AuthentikProxyProviderReconciler{Client: kube, Scheme: scheme}
			if _, err := r.reconcileNormal(context.Background(), p, server, authentik.NewClient(srv.URL, "test-token", false, "")); err == nil {
				t.Fatal("access failure reported success")
			}
			var saved authv1.AuthentikProxyProvider
			checkTestError(t, kube.Get(context.Background(), types.NamespacedName{Name: p.Name, Namespace: p.Namespace}, &saved))
			if saved.Status.Ready || saved.Status.ProviderID != 0 {
				t.Fatalf("unsafe status: %+v", saved.Status)
			}
			if app["provider"] != nil || app["policy_engine_mode"] != "all" || app["meta_description"] != "Managed by AuthentikClient proxy-uid" {
				t.Fatalf("application not left closed and owned: %+v", app)
			}
		})
	}
}
