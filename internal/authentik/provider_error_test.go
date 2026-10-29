package authentik

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProviderCreateErrorExcludesSensitiveResponse(t *testing.T) {
	for _, status := range []int{400, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = fmt.Fprint(w, `{"client_secret":"sensitive-response-marker"}`)
			}))
			defer srv.Close()
			_, err := NewClient(srv.URL, "sensitive-token-marker", false, "").CreateOAuth2Provider(context.Background(), "example", "auth-flow", "invalidation-flow", []string{"https://example.test/callback"}, "confidential", []string{}, "client-id", "", nil, "")
			if err == nil || !strings.Contains(err.Error(), fmt.Sprint(status)) {
				t.Fatalf("expected bounded status error, got %v", err)
			}
			if strings.Contains(err.Error(), "sensitive-") || strings.Contains(err.Error(), "client_secret") {
				t.Fatal("provider error exposed sensitive response or token")
			}
		})
	}
}
