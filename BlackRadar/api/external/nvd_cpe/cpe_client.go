// Package cpeclient provides a small client for the official NVD CPE API.
package cpeclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	providerquota "blackradar/api/external/provider_quota"
	externalratelimiter "blackradar/api/external/rate_limiter"
)

const officialCPEHost = "services.nvd.nist.gov"

// CPEClient searches the official NVD CPE API for candidate product matches.
type CPEClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	limiter    *externalratelimiter.RateLimiter
	quota      providerquota.Reserver
}

// NewCPEClient creates a CPE client with host allowlist, timeouts, and rate limits.
func NewCPEClient(baseURL string, apiKey string) (*CPEClient, error) {
	limit := 5
	if strings.TrimSpace(apiKey) != "" {
		limit = 50
	}
	return NewCPEClientWithHTTPClient(baseURL, apiKey, newHTTPClient(), externalratelimiter.NewRateLimiter(limit, 30*time.Second))
}

// NewCPEClientWithQuota creates a production CPE client with durable quota enforcement.
func NewCPEClientWithQuota(baseURL string, apiKey string, quota providerquota.Reserver) (*CPEClient, error) {
	limit := nvdQuotaLimit(apiKey)
	return NewCPEClientWithHTTPClientAndQuota(baseURL, apiKey, newHTTPClient(), externalratelimiter.NewRateLimiter(limit, 30*time.Second), quota)
}

// NewCPEClientWithHTTPClient creates a CPE client for tests or controlled wiring.
func NewCPEClientWithHTTPClient(baseURL string, apiKey string, httpClient *http.Client, limiter *externalratelimiter.RateLimiter) (*CPEClient, error) {
	return NewCPEClientWithHTTPClientAndQuota(baseURL, apiKey, httpClient, limiter, nil)
}

// NewCPEClientWithHTTPClientAndQuota creates a CPE client with local and durable request limits.
func NewCPEClientWithHTTPClientAndQuota(baseURL string, apiKey string, httpClient *http.Client, limiter *externalratelimiter.RateLimiter, quota providerquota.Reserver) (*CPEClient, error) {
	normalizedBaseURL, err := validateCPEBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	if limiter == nil {
		limiter = externalratelimiter.NewRateLimiter(5, 30*time.Second)
	}
	return &CPEClient{
		baseURL:    normalizedBaseURL,
		apiKey:     strings.TrimSpace(apiKey),
		httpClient: httpClient,
		limiter:    limiter,
		quota:      quota,
	}, nil
}

// SearchCandidates returns CPE candidates for a normalized search request.
func (c *CPEClient) SearchCandidates(ctx context.Context, request CPEMatchRequest) ([]CPECandidate, error) {
	hasKeywordSearch := strings.TrimSpace(request.KeywordSearch) != ""
	hasCPEMatchString := strings.TrimSpace(request.CPEMatchString) != ""
	if hasKeywordSearch == hasCPEMatchString {
		return nil, ErrInvalidCPESearch
	}

	keywordSearch := normalizeCPEKeywordSearch(request.KeywordSearch)
	cpeMatchString := normalizeCPEMatchString(request.CPEMatchString)
	if (hasKeywordSearch && keywordSearch == "") || (hasCPEMatchString && cpeMatchString == "") {
		return nil, ErrInvalidCPESearch
	}
	if !c.limiter.Allow(time.Now()) {
		return nil, ErrNVDRateLimited
	}
	if c.quota != nil {
		if err := c.quota.Reserve(ctx, providerquota.NVD, time.Now(), nvdQuotaLimit(c.apiKey), 30*time.Second); err != nil {
			if errors.Is(err, providerquota.ErrExceeded) {
				return nil, ErrNVDRateLimited
			}
			return nil, ErrNVDUnavailable
		}
	}

	requestURL, err := c.searchURL(CPEMatchRequest{
		CPEMatchString: cpeMatchString,
		KeywordSearch:  keywordSearch,
	})
	if err != nil {
		return nil, err
	}

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request", ErrNVDUnavailable)
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("User-Agent", "BlackRadar API NVD client")
	if c.apiKey != "" {
		httpRequest.Header.Set("apiKey", c.apiKey)
	}

	response, err := c.httpClient.Do(httpRequest)
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

	var payload cpeAPIResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("%w: decode response", ErrInvalidNVDResponse)
	}
	if len(payload.Products) == 0 {
		return []CPECandidate{}, nil
	}

	candidates := make([]CPECandidate, 0, len(payload.Products))
	for _, product := range payload.Products {
		candidate := mapCPECandidate(product.CPE)
		if candidate.CPEName == "" {
			continue
		}
		candidates = append(candidates, candidate)
		if len(candidates) >= 10 {
			break
		}
	}

	return candidates, nil
}

func nvdQuotaLimit(apiKey string) int {
	if strings.TrimSpace(apiKey) != "" {
		return 50
	}
	return 5
}
