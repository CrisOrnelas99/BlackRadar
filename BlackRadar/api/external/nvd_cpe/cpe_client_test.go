// Package cpeclient verifies the CPE search client behavior.
package cpeclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"blackradar/api/controller/dto"
	externalratelimiter "blackradar/api/external/rate_limiter"
)

func TestCPEClientSearchCandidates(t *testing.T) {
	var receivedQuery string
	var receivedAPIKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		receivedAPIKey = r.Header.Get("apiKey")
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/rest/json/cpes/2.0" {
			t.Fatalf("expected cpe search path, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"products":[{"cpe":{"cpeName":"cpe:2.3:a:dell:latitude_7420:*:*:*:*:*:*:*:*","deprecated":false,"titles":[{"lang":"en","title":"Dell Latitude 7420"}]}}]}`))
	}))
	defer server.Close()

	client, err := NewCPEClientWithHTTPClient(server.URL+"/rest/json/cpes/2.0", "test-key", server.Client(), externalratelimiter.NewRateLimiter(10, 30*time.Second))
	if err != nil {
		t.Fatalf("expected client creation to succeed, got %v", err)
	}

	candidates, err := client.SearchCandidates(context.Background(), dto.CPEMatchRequest{KeywordSearch: "dell latitude 7420"})
	if err != nil {
		t.Fatalf("expected search to succeed, got %v", err)
	}
	if !strings.Contains(receivedQuery, "keywordSearch=dell+latitude+7420") {
		t.Fatalf("expected keyword search query, got %q", receivedQuery)
	}
	if receivedAPIKey != "test-key" {
		t.Fatalf("expected apiKey header test-key, got %q", receivedAPIKey)
	}
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}
	if candidates[0].CPEName != "cpe:2.3:a:dell:latitude_7420:*:*:*:*:*:*:*:*" {
		t.Fatalf("unexpected candidate cpe name %q", candidates[0].CPEName)
	}
}
