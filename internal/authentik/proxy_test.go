package authentik

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func desiredProxy() ProxyProvider {
	return ProxyProvider{Name: "prod-whoami", AuthorizationFlow: "flow-a", InvalidationFlow: "flow-i", ExternalHost: "https://whoami.example.com", Mode: "forward_single", AccessTokenValidity: "hours=8"}
}

func TestProxyProviderOwnership(t *testing.T) {
	for _, tc := range []struct {
		name      string
		existing  *ProxyProvider
		knownID   int32
		wantErr   bool
		wantWrite string
	}{
		{name: "create", wantWrite: http.MethodPost},
		{name: "unchanged", existing: func() *ProxyProvider { p := desiredProxy(); p.PK = 5; return &p }(), knownID: 5},
		{name: "drift repaired", existing: func() *ProxyProvider { p := desiredProxy(); p.PK = 5; p.ExternalHost = "https://other"; return &p }(), knownID: 5, wantWrite: http.MethodPatch},
		{name: "unassigned name match refused", existing: func() *ProxyProvider { p := desiredProxy(); p.PK = 5; return &p }(), wantErr: true},
		{name: "own application name match refused without recorded ID", existing: func() *ProxyProvider {
			p := desiredProxy()
			p.PK = 5
			p.AssignedApplicationSlug = "prod-whoami"
			return &p
		}(), wantErr: true},
		{name: "recorded ID assigned elsewhere refused", existing: func() *ProxyProvider {
			p := desiredProxy()
			p.PK = 5
			p.AssignedApplicationSlug = "someone-else"
			return &p
		}(), knownID: 5, wantErr: true},
		{name: "recorded ID after status loss is reused", existing: func() *ProxyProvider { p := desiredProxy(); p.PK = 5; return &p }(), knownID: 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stored := tc.existing
			writes := []string{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/v3/providers/proxy/":
					list := []ProxyProvider{}
					if stored != nil {
						list = append(list, *stored)
					}
					checkTestError(t, json.NewEncoder(w).Encode(map[string]any{"results": list, "pagination": map[string]int{"next": 0}}))
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v3/providers/proxy/"):
					if stored == nil {
						w.WriteHeader(404)
						return
					}
					checkTestError(t, json.NewEncoder(w).Encode(stored))
				case r.Method == http.MethodPost || r.Method == http.MethodPatch:
					writes = append(writes, r.Method)
					var p ProxyProvider
					checkTestError(t, json.NewDecoder(r.Body).Decode(&p))
					p.PK = 5
					stored = &p
					checkTestError(t, json.NewEncoder(w).Encode(p))
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					w.WriteHeader(500)
				}
			}))
			defer srv.Close()
			c := NewClient(srv.URL, "private-token", false, "")
			got, err := c.ReconcileProxyProvider(context.Background(), ProxyPlan{Desired: desiredProxy(), KnownID: tc.knownID, AppSlug: "prod-whoami"})
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v", err)
			}
			if tc.wantErr {
				if len(writes) != 0 {
					t.Fatal("modified a provider this resource does not own")
				}
				return
			}
			if (tc.wantWrite == "" && len(writes) != 0) || (tc.wantWrite != "" && (len(writes) != 1 || writes[0] != tc.wantWrite)) {
				t.Fatalf("writes=%v", writes)
			}
			if got.PK != 5 || !proxyMatches(*got, desiredProxy()) {
				t.Fatalf("unexpected provider %+v", got)
			}
		})
	}
}

func outpostServer(t *testing.T, o *outpost, writes *int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/outposts/instances/":
			if r.URL.Query().Get("managed__iexact") != embeddedOutpostManaged {
				t.Errorf("outpost query not restricted to the embedded outpost: %s", r.URL.RawQuery)
			}
			foreign := outpost{PK: "other", Managed: "", Providers: []int32{1}}
			checkTestError(t, json.NewEncoder(w).Encode(map[string]any{"results": []outpost{foreign, *o}, "pagination": map[string]int{"next": 0}}))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/outposts/instances/emb/":
			checkTestError(t, json.NewEncoder(w).Encode(o))
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v3/outposts/instances/emb/":
			*writes++
			var patch outpost
			checkTestError(t, json.NewDecoder(r.Body).Decode(&patch))
			o.Providers = patch.Providers
			if patch.Config != nil {
				o.Config = patch.Config
			}
			_, _ = fmt.Fprint(w, `{}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	}))
}

func TestEmbeddedOutpostAttachment(t *testing.T) {
	o := &outpost{PK: "emb", Managed: embeddedOutpostManaged, Providers: []int32{3}, Config: map[string]any{"authentik_host": "http://auth.example.com", "log_level": "info"}}
	writes := 0
	srv := outpostServer(t, o, &writes)
	defer srv.Close()
	c := NewClient(srv.URL, "private-token", false, "")

	id, err := c.AttachToEmbeddedOutpost(context.Background(), 5, "https://auth.example.com")
	if err != nil || id != "emb" {
		t.Fatalf("attach id=%q err=%v", id, err)
	}
	if !slices.Equal(o.Providers, []int32{3, 5}) || o.Config["authentik_host"] != "https://auth.example.com" || o.Config["log_level"] != "info" {
		t.Fatalf("foreign providers or config not preserved: %+v", o)
	}
	if _, err := c.AttachToEmbeddedOutpost(context.Background(), 5, "https://auth.example.com"); err != nil || writes != 1 {
		t.Fatalf("attach is not idempotent: writes=%d err=%v", writes, err)
	}
	if err := c.DetachFromEmbeddedOutpost(context.Background(), 5); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(o.Providers, []int32{3}) || o.Config["authentik_host"] != "https://auth.example.com" {
		t.Fatalf("detach touched more than its own provider: %+v", o)
	}
}

func TestEmbeddedOutpostVerificationFailure(t *testing.T) {
	o := &outpost{PK: "emb", Managed: embeddedOutpostManaged, Providers: []int32{}, Config: map[string]any{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/outposts/instances/":
			checkTestError(t, json.NewEncoder(w).Encode(map[string]any{"results": []outpost{*o}, "pagination": map[string]int{"next": 0}}))
		case r.Method == http.MethodPatch:
			_, _ = fmt.Fprint(w, `{}`) // accepted but silently not applied
		default:
			checkTestError(t, json.NewEncoder(w).Encode(o))
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "private-token", false, "")
	if _, err := c.AttachToEmbeddedOutpost(context.Background(), 5, "https://auth.example.com"); err == nil {
		t.Fatal("unverified attachment reported success")
	}
}
