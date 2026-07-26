// Package cveclient provides a small client for the official NVD CVE API.
package cveclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	externalratelimiter "blackradar/api/external/rate_limiter"
)

const (
	officialNVDHost = "services.nvd.nist.gov"
	nvdRetryDelay   = 6 * time.Second
)

// Client looks up CVE details from the official NVD CVE API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	limiter    *externalratelimiter.RateLimiter
	retryDelay time.Duration
	sleep      func(context.Context, time.Duration) error
}

// NewClient creates an NVD client with host allowlist, timeouts, and rate limits.
func NewClient(baseURL string, apiKey string) (*Client, error) {
	limit := 5
	if strings.TrimSpace(apiKey) != "" {
		limit = 50
	}
	return NewClientWithHTTPClient(baseURL, apiKey, newHTTPClient(), externalratelimiter.NewRateLimiter(limit, 30*time.Second))
}

// NewClientWithHTTPClient creates an NVD client for tests or controlled wiring.
func NewClientWithHTTPClient(baseURL string, apiKey string, httpClient *http.Client, limiter *externalratelimiter.RateLimiter) (*Client, error) {
	normalizedBaseURL, err := validateBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	if limiter == nil {
		limiter = externalratelimiter.NewRateLimiter(5, 30*time.Second)
	}
	return &Client{
		baseURL:    normalizedBaseURL,
		apiKey:     strings.TrimSpace(apiKey),
		httpClient: httpClient,
		limiter:    limiter,
		retryDelay: nvdRetryDelay,
		sleep:      sleepWithContext,
	}, nil
}

// LookupCVE retrieves a single CVE record from NVD and maps it to the app DTO.
func (c *Client) LookupCVE(ctx context.Context, cveID string) (CVELookupResponse, error) {
	normalizedCVEID := normalizeCVEID(cveID)
	if err := validateCVEID(normalizedCVEID); err != nil {
		return CVELookupResponse{}, ErrInvalidCVEID
	}
	if !c.limiter.Allow(time.Now()) {
		return CVELookupResponse{}, ErrNVDRateLimited
	}

	requestURL, err := c.lookupURL(normalizedCVEID)
	if err != nil {
		return CVELookupResponse{}, err
	}

	response, err := c.doRequestWithRetry(ctx, requestURL)
	if err != nil {
		return CVELookupResponse{}, fmt.Errorf("%w: request failed", ErrNVDUnavailable)
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusTooManyRequests:
		return CVELookupResponse{}, ErrNVDRateLimited
	case http.StatusNotFound:
		return CVELookupResponse{}, ErrCVEIDNotFound
	default:
		return CVELookupResponse{}, fmt.Errorf("%w: status %d", ErrNVDUnavailable, response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return CVELookupResponse{}, fmt.Errorf("%w: read response", ErrNVDUnavailable)
	}

	var payload cveAPIResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return CVELookupResponse{}, fmt.Errorf("%w: decode response", ErrInvalidNVDResponse)
	}
	if payload.TotalResults == 0 || len(payload.Vulnerabilities) == 0 {
		return CVELookupResponse{}, ErrCVEIDNotFound
	}

	cve := payload.Vulnerabilities[0].CVE
	if normalizeCVEID(cve.ID) != normalizedCVEID {
		return CVELookupResponse{}, ErrInvalidNVDResponse
	}

	return mapCVE(cve), nil
}

// SearchCVEsByCPE retrieves vulnerable CVE records for an exact NVD CPE name.
func (c *Client) SearchCVEsByCPE(ctx context.Context, cpeName string, limit int) ([]CVELookupResponse, error) {
	cpeName = strings.TrimSpace(cpeName)
	if !strings.HasPrefix(cpeName, "cpe:2.3:") {
		return nil, ErrInvalidCPESearch
	}
	if limit <= 0 || limit > 20 {
		limit = 10
	}
	if !c.limiter.Allow(time.Now()) {
		return nil, ErrNVDRateLimited
	}

	requestURL, err := c.cpeSearchURL(cpeName, limit)
	if err != nil {
		return nil, err
	}

	response, err := c.doRequestWithRetry(ctx, requestURL)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed", ErrNVDUnavailable)
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusTooManyRequests:
		return nil, ErrNVDRateLimited
	default:
		return nil, fmt.Errorf("%w: status %d", ErrNVDUnavailable, response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read response", ErrNVDUnavailable)
	}

	var payload cveAPIResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("%w: decode response", ErrInvalidNVDResponse)
	}
	if payload.TotalResults == 0 || len(payload.Vulnerabilities) == 0 {
		return []CVELookupResponse{}, nil
	}

	results := make([]CVELookupResponse, 0, min(limit, len(payload.Vulnerabilities)))
	for _, vulnerability := range payload.Vulnerabilities {
		if strings.TrimSpace(vulnerability.CVE.ID) == "" {
			continue
		}
		results = append(results, mapCVE(vulnerability.CVE))
		if len(results) >= limit {
			break
		}
	}

	return results, nil
}

// SearchCVEsByKeyword retrieves CVE records from NVD for a bounded backend-generated keyword search.
func (c *Client) SearchCVEsByKeyword(ctx context.Context, keywordSearch string, limit int) ([]CVELookupResponse, error) {
	keywordSearch = normalizeCVEKeywordSearch(keywordSearch)
	if keywordSearch == "" {
		return nil, ErrInvalidCVESearch
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if !c.limiter.Allow(time.Now()) {
		return nil, ErrNVDRateLimited
	}

	requestURL, err := c.keywordSearchURL(keywordSearch, limit)
	if err != nil {
		return nil, err
	}

	response, err := c.doRequestWithRetry(ctx, requestURL)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed", ErrNVDUnavailable)
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusTooManyRequests:
		return nil, ErrNVDRateLimited
	default:
		return nil, fmt.Errorf("%w: status %d", ErrNVDUnavailable, response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read response", ErrNVDUnavailable)
	}

	var payload cveAPIResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("%w: decode response", ErrInvalidNVDResponse)
	}
	if payload.TotalResults == 0 || len(payload.Vulnerabilities) == 0 {
		return []CVELookupResponse{}, nil
	}

	results := make([]CVELookupResponse, 0, min(limit, len(payload.Vulnerabilities)))
	for _, vulnerability := range payload.Vulnerabilities {
		if strings.TrimSpace(vulnerability.CVE.ID) == "" {
			continue
		}
		results = append(results, mapCVE(vulnerability.CVE))
		if len(results) >= limit {
			break
		}
	}

	return results, nil
}
