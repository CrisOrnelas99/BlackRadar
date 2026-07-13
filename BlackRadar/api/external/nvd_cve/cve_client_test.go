// Package cveclient verifies the NVD API client and response mapping.
package cveclient

import (
	externalratelimiter "blackradar/api/external/rate_limiter"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestClientLookupCVE verifies request construction and safe DTO mapping.
func TestClientLookupCVE(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host != officialNVDHost {
			t.Fatalf("expected official NVD host, got %q", request.URL.Host)
		}
		if request.URL.Query().Get("cveIds") != "CVE-2021-44228" {
			t.Fatalf("expected cveIds query, got %q", request.URL.RawQuery)
		}
		if request.Header.Get("User-Agent") != "BlackRadar API NVD client" {
			t.Fatalf("expected user agent to be set, got %q", request.Header.Get("User-Agent"))
		}
		if request.Header.Get("apiKey") != "server-side-key" {
			t.Fatal("expected API key to be sent as a server-side header")
		}

		body := `{
			"totalResults": 1,
			"vulnerabilities": [{
				"cve": {
					"id": "CVE-2021-44228",
					"published": "2021-12-10T10:15:09.067",
					"lastModified": "2024-11-21T12:15:26.783",
					"descriptions": [{"lang": "en", "value": "Apache Log4j remote code execution."}],
					"metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]}
				}
			}]
		}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})

	client, err := NewClientWithHTTPClient(
		"https://services.nvd.nist.gov/rest/json/cves/2.0",
		"server-side-key",
		&http.Client{Transport: transport},
		externalratelimiter.NewRateLimiter(10, time.Second),
	)
	if err != nil {
		t.Fatalf("expected client to build, got %v", err)
	}

	response, err := client.LookupCVE(context.Background(), " cve-2021-44228 ")
	if err != nil {
		t.Fatalf("expected lookup to succeed, got %v", err)
	}
	if response.CVEID != "CVE-2021-44228" {
		t.Fatalf("expected normalized CVE ID, got %q", response.CVEID)
	}
	if response.Severity != "CRITICAL" {
		t.Fatalf("expected severity CRITICAL, got %q", response.Severity)
	}
	if response.NVDURL != "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" {
		t.Fatalf("unexpected NVD URL: %q", response.NVDURL)
	}
}

func TestClientSearchCVEsByCPE(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Query().Get("cpeName") != "cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*" {
			t.Fatalf("expected cpeName query, got %q", request.URL.RawQuery)
		}
		if _, ok := request.URL.Query()["isVulnerable"]; !ok {
			t.Fatalf("expected isVulnerable query, got %q", request.URL.RawQuery)
		}
		if request.URL.Query().Get("resultsPerPage") != "5" {
			t.Fatalf("expected resultsPerPage 5, got %q", request.URL.RawQuery)
		}

		body := `{
			"totalResults": 1,
			"vulnerabilities": [{
				"cve": {
					"id": "CVE-2024-3094",
					"descriptions": [{"lang": "en", "value": "XZ Utils backdoor."}],
					"metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]}
				}
			}]
		}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})

	client, err := NewClientWithHTTPClient(
		"https://services.nvd.nist.gov/rest/json/cves/2.0",
		"server-side-key",
		&http.Client{Transport: transport},
		externalratelimiter.NewRateLimiter(10, time.Second),
	)
	if err != nil {
		t.Fatalf("expected client to build, got %v", err)
	}

	results, err := client.SearchCVEsByCPE(context.Background(), "cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*", 5)
	if err != nil {
		t.Fatalf("expected CPE search to succeed, got %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one CVE, got %d", len(results))
	}
	if results[0].CVEID != "CVE-2024-3094" {
		t.Fatalf("expected CVE-2024-3094, got %q", results[0].CVEID)
	}
}

func TestClientSearchCVEsByKeyword(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Query().Get("keywordSearch") != "WP-Ultimate-Map" {
			t.Fatalf("expected keywordSearch query, got %q", request.URL.RawQuery)
		}
		if request.URL.Query().Get("resultsPerPage") != "50" {
			t.Fatalf("expected resultsPerPage 50, got %q", request.URL.RawQuery)
		}
		if request.Header.Get("apiKey") != "server-side-key" {
			t.Fatal("expected API key to be sent as a server-side header")
		}

		body := `{
			"totalResults": 1,
			"vulnerabilities": [{
				"cve": {
					"id": "CVE-2026-12345",
					"descriptions": [{"lang": "en", "value": "WP-Ultimate-Map plugin for WordPress is vulnerable."}],
					"metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]}
				}
			}]
		}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})

	client, err := NewClientWithHTTPClient(
		"https://services.nvd.nist.gov/rest/json/cves/2.0",
		"server-side-key",
		&http.Client{Transport: transport},
		externalratelimiter.NewRateLimiter(10, time.Second),
	)
	if err != nil {
		t.Fatalf("expected client to build, got %v", err)
	}

	results, err := client.SearchCVEsByKeyword(context.Background(), " WP-Ultimate-Map ", 50)
	if err != nil {
		t.Fatalf("expected keyword search to succeed, got %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one CVE, got %d", len(results))
	}
	if results[0].CVEID != "CVE-2026-12345" {
		t.Fatalf("expected CVE-2026-12345, got %q", results[0].CVEID)
	}
	if results[0].Severity != "HIGH" {
		t.Fatalf("expected severity HIGH, got %q", results[0].Severity)
	}
}

func TestClientSearchCVEsByKeywordEncodesSpacesAsPercent20(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if !strings.Contains(request.URL.RawQuery, "keywordSearch=amazon%20web%20services") {
			t.Fatalf("expected keyword spaces to be encoded as percent-20, got %q", request.URL.RawQuery)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"totalResults":0,"vulnerabilities":[]}`)),
			Header:     make(http.Header),
		}, nil
	})

	client, err := NewClientWithHTTPClient(
		"https://services.nvd.nist.gov/rest/json/cves/2.0",
		"",
		&http.Client{Transport: transport},
		externalratelimiter.NewRateLimiter(10, time.Second),
	)
	if err != nil {
		t.Fatalf("expected client to build, got %v", err)
	}

	_, err = client.SearchCVEsByKeyword(context.Background(), "amazon web services", 100)
	if err != nil {
		t.Fatalf("expected encoded keyword search to succeed, got %v", err)
	}
}

func TestClientSearchCVEsByKeywordRetriesServiceUnavailable(t *testing.T) {
	requestCount := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requestCount++
		if requestCount == 1 {
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Body:       io.NopCloser(strings.NewReader(`{"message":"temporary unavailable"}`)),
				Header:     make(http.Header),
			}, nil
		}

		body := `{
			"totalResults": 1,
			"vulnerabilities": [{
				"cve": {
					"id": "CVE-2026-12345",
					"descriptions": [{"lang": "en", "value": "Ultimate Map plugin for WordPress is vulnerable."}],
					"metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]}
				}
			}]
		}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})

	client, err := NewClientWithHTTPClient(
		"https://services.nvd.nist.gov/rest/json/cves/2.0",
		"server-side-key",
		&http.Client{Transport: transport},
		externalratelimiter.NewRateLimiter(10, time.Second),
	)
	if err != nil {
		t.Fatalf("expected client to build, got %v", err)
	}
	client.retryDelay = 0

	results, err := client.SearchCVEsByKeyword(context.Background(), "ultimate map", 20)
	if err != nil {
		t.Fatalf("expected retry to succeed, got %v", err)
	}
	if requestCount != 2 {
		t.Fatalf("expected one retry after 503, got %d requests", requestCount)
	}
	if len(results) != 1 || results[0].CVEID != "CVE-2026-12345" {
		t.Fatalf("expected retried CVE result, got %#v", results)
	}
}

func TestClientSearchCVEsByKeywordRetriesTimeout(t *testing.T) {
	requestCount := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requestCount++
		if requestCount == 1 {
			return nil, context.DeadlineExceeded
		}

		body := `{
			"totalResults": 1,
			"vulnerabilities": [{
				"cve": {
					"id": "CVE-2026-12345",
					"descriptions": [{"lang": "en", "value": "Ultimate Map plugin for WordPress is vulnerable."}]
				}
			}]
		}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})

	client, err := NewClientWithHTTPClient(
		"https://services.nvd.nist.gov/rest/json/cves/2.0",
		"",
		&http.Client{Transport: transport},
		externalratelimiter.NewRateLimiter(10, time.Second),
	)
	if err != nil {
		t.Fatalf("expected client to build, got %v", err)
	}
	client.retryDelay = 0

	_, err = client.SearchCVEsByKeyword(context.Background(), "ultimate map", 20)
	if err != nil {
		t.Fatalf("expected timeout retry to succeed, got %v", err)
	}
	if requestCount != 2 {
		t.Fatalf("expected one retry after timeout, got %d requests", requestCount)
	}
}

// TestClientRejectsUnsafeBaseURL verifies outbound host allowlisting.
func TestClientRejectsUnsafeBaseURL(t *testing.T) {
	_, err := NewClientWithHTTPClient("https://example.com/rest/json/cves/2.0", "", nil, nil)
	if !errors.Is(err, ErrInvalidNVDBaseURL) {
		t.Fatalf("expected invalid base URL error, got %v", err)
	}
}

// TestClientRestrictsRedirects verifies the production client does not follow redirects.
func TestClientRestrictsRedirects(t *testing.T) {
	client, err := NewClient("https://services.nvd.nist.gov/rest/json/cves/2.0", "")
	if err != nil {
		t.Fatalf("expected client to build, got %v", err)
	}
	if client.httpClient.CheckRedirect == nil {
		t.Fatal("expected redirect policy to be configured")
	}

	redirectRequest, err := http.NewRequest(http.MethodGet, "https://example.com/redirect", nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	originalRequest, err := http.NewRequest(http.MethodGet, "https://services.nvd.nist.gov/rest/json/cves/2.0", nil)
	if err != nil {
		t.Fatalf("failed to build original request: %v", err)
	}

	err = client.httpClient.CheckRedirect(redirectRequest, []*http.Request{originalRequest})
	if !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("expected redirect to be blocked, got %v", err)
	}
}

// TestClientHandlesNVDNotFound verifies empty NVD results map to not found.
func TestClientHandlesNVDNotFound(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"totalResults":0,"vulnerabilities":[]}`)),
			Header:     make(http.Header),
		}, nil
	})
	client, err := NewClientWithHTTPClient(
		"https://services.nvd.nist.gov/rest/json/cves/2.0",
		"",
		&http.Client{Transport: transport},
		externalratelimiter.NewRateLimiter(10, time.Second),
	)
	if err != nil {
		t.Fatalf("expected client to build, got %v", err)
	}

	_, err = client.LookupCVE(context.Background(), "CVE-2021-44228")
	if !errors.Is(err, ErrCVEIDNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

// TestClientRejectsMismatchedCVEID verifies external response identity is checked.
func TestClientRejectsMismatchedCVEID(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(`{
				"totalResults": 1,
				"vulnerabilities": [{
					"cve": {
						"id": "CVE-1999-0001",
						"descriptions": [{"lang": "en", "value": "wrong record"}]
					}
				}]
			}`)),
			Header: make(http.Header),
		}, nil
	})
	client, err := NewClientWithHTTPClient(
		"https://services.nvd.nist.gov/rest/json/cves/2.0",
		"",
		&http.Client{Transport: transport},
		externalratelimiter.NewRateLimiter(10, time.Second),
	)
	if err != nil {
		t.Fatalf("expected client to build, got %v", err)
	}

	_, err = client.LookupCVE(context.Background(), "CVE-2021-44228")
	if !errors.Is(err, ErrInvalidNVDResponse) {
		t.Fatalf("expected invalid NVD response, got %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
