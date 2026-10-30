package authentik

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

const emptyApplications = `{"autocomplete":{},"pagination":{"count":0,"next":0,"previous":0,"current":1,"total_pages":1,"start_index":0,"end_index":0},"results":[]}`

func TestFreshClientsReuseConnections(t *testing.T) {
	// Reconciliation constructs a new API client each time. A local server
	// observes the resource lifetime through the same interface as controllers.
	for _, tc := range []struct {
		insecure bool
		status   int
	}{
		{false, http.StatusOK}, {true, http.StatusOK},
		{false, http.StatusServiceUnavailable}, {true, http.StatusServiceUnavailable},
	} {
		t.Run(fmt.Sprintf("insecure=%t/status=%d", tc.insecure, tc.status), func(t *testing.T) {
			var accepted atomic.Int64
			var requests atomic.Int64
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				request := requests.Add(1)
				// Sharing connection pools must not share credentials between clients.
				if got, want := r.Header.Get("Authorization"), fmt.Sprintf("Bearer synthetic-%d", request); got != want {
					t.Errorf("authorization = %q, want %q", got, want)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(emptyApplications))
			}))
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					accepted.Add(1)
				}
			}
			server.Start()
			defer server.Close()
			for request := 1; request <= 100; request++ {
				client := NewClient(server.URL, fmt.Sprintf("synthetic-%d", request), tc.insecure, "")
				if err := client.HealthCheck(context.Background()); (err != nil) != (tc.status != http.StatusOK) {
					t.Fatalf("HealthCheck status %d: unexpected error %v", tc.status, err)
				}
			}
			if got := requests.Load(); got != 100 {
				t.Fatalf("requests = %d, want 100", got)
			}
			if got := accepted.Load(); got > 2 {
				t.Errorf("100 successive reconciliations opened %d connections; want at most 2", got)
			}
		})
	}
}

func TestClientTLSModesRemainIsolated(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(emptyApplications))
	}))
	defer server.Close()
	if err := NewClient(server.URL, "synthetic", true, "").HealthCheck(context.Background()); err != nil {
		t.Fatalf("explicit insecure client should accept the test certificate: %v", err)
	}
	if err := NewClient(server.URL, "synthetic", false, "").HealthCheck(context.Background()); err == nil {
		t.Fatal("a verifying client must reject the self-signed certificate after an insecure client used it")
	}
}
