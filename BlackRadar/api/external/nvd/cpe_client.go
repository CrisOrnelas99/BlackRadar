// Package nvd provides a small client for the official NVD CPE API.
package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"blackradar/api/dto"
)

const officialCPEHost = "services.nvd.nist.gov"

// CPEClient searches the official NVD CPE API for candidate product matches.
type CPEClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	limiter    *RateLimiter
}

// NewCPEClient creates a CPE client with host allowlist, timeouts, and rate limits.
func NewCPEClient(baseURL string, apiKey string) (*CPEClient, error) {
	limit := 5
	if strings.TrimSpace(apiKey) != "" {
		limit = 50
	}
	return NewCPEClientWithHTTPClient(baseURL, apiKey, newHTTPClient(), NewRateLimiter(limit, 30*time.Second))
}

// NewCPEClientWithHTTPClient creates a CPE client for tests or controlled wiring.
func NewCPEClientWithHTTPClient(baseURL string, apiKey string, httpClient *http.Client, limiter *RateLimiter) (*CPEClient, error) {
	normalizedBaseURL, err := validateCPEBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	if limiter == nil {
		limiter = NewRateLimiter(5, 30*time.Second)
	}
	return &CPEClient{
		baseURL:    normalizedBaseURL,
		apiKey:     strings.TrimSpace(apiKey),
		httpClient: httpClient,
		limiter:    limiter,
	}, nil
}

// SearchCandidates returns CPE candidates for a normalized search request.
func (c *CPEClient) SearchCandidates(ctx context.Context, request dto.CPEMatchRequest) ([]dto.CPECandidate, error) {
	keywordSearch := strings.TrimSpace(request.KeywordSearch)
	if keywordSearch == "" {
		return nil, ErrInvalidCPESearch
	}
	if !c.limiter.Allow(time.Now()) {
		return nil, ErrNVDRateLimited
	}

	requestURL, err := c.searchURL(keywordSearch)
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
		return []dto.CPECandidate{}, nil
	}

	candidates := make([]dto.CPECandidate, 0, len(payload.Products))
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

func (c *CPEClient) searchURL(keywordSearch string) (string, error) {
	parsed, err := url.Parse(c.baseURL)
	if err != nil {
		return "", ErrInvalidBaseURL
	}
	values := parsed.Query()
	values.Set("keywordSearch", keywordSearch)
	parsed.RawQuery = values.Encode()
	return parsed.String(), nil
}

func validateCPEBaseURL(baseURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", ErrInvalidBaseURL
	}
	if parsed.Path != "/rest/json/cpes/2.0" {
		return "", ErrInvalidBaseURL
	}
	if parsed.Scheme == "https" && parsed.Host == officialCPEHost {
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return parsed.String(), nil
	}
	if parsed.Scheme == "http" && isLocalHost(parsed.Hostname()) {
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return parsed.String(), nil
	}
	return "", ErrInvalidBaseURL
}

func isLocalHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

type cpeAPIResponse struct {
	Products []cpeProductItem `json:"products"`
}

type cpeProductItem struct {
	CPE cpeItem `json:"cpe"`
}

type cpeItem struct {
	CPEName    string  `json:"cpeName"`
	Deprecated bool    `json:"deprecated"`
	Titles     []title `json:"titles"`
}

type title struct {
	Lang  string `json:"lang"`
	Title string `json:"title"`
}

func mapCPECandidate(cpe cpeItem) dto.CPECandidate {
	title := cpe.CPEName
	for _, entry := range cpe.Titles {
		if strings.EqualFold(entry.Lang, "en") && strings.TrimSpace(entry.Title) != "" {
			title = strings.TrimSpace(entry.Title)
			break
		}
	}

	return dto.CPECandidate{
		CPEName:    strings.TrimSpace(cpe.CPEName),
		Title:      title,
		Deprecated: cpe.Deprecated,
	}
}
