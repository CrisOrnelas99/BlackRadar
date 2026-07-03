// Package nvd provides a small client for the official NVD CVE API.
package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"secureops/backend-go/api/dto"
	baseservice "secureops/backend-go/api/service"
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
	limiter    *RateLimiter
	retryDelay time.Duration
	sleep      func(context.Context, time.Duration) error
}

// NewClient creates an NVD client with host allowlist, timeouts, and rate limits.
func NewClient(baseURL string, apiKey string) (*Client, error) {
	limit := 5
	if strings.TrimSpace(apiKey) != "" {
		limit = 50
	}
	return NewClientWithHTTPClient(baseURL, apiKey, newHTTPClient(), NewRateLimiter(limit, 30*time.Second))
}

// NewClientWithHTTPClient creates an NVD client for tests or controlled wiring.
func NewClientWithHTTPClient(baseURL string, apiKey string, httpClient *http.Client, limiter *RateLimiter) (*Client, error) {
	normalizedBaseURL, err := validateBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	if limiter == nil {
		limiter = NewRateLimiter(5, 30*time.Second)
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
func (c *Client) LookupCVE(ctx context.Context, cveID string) (dto.CVELookupResponse, error) {
	normalizedCVEID := baseservice.NormalizeCVEID(cveID)
	if err := baseservice.ValidateCVEID(normalizedCVEID); err != nil {
		return dto.CVELookupResponse{}, ErrInvalidCVEID
	}
	if !c.limiter.Allow(time.Now()) {
		return dto.CVELookupResponse{}, ErrNVDRateLimited
	}

	requestURL, err := c.lookupURL(normalizedCVEID)
	if err != nil {
		return dto.CVELookupResponse{}, err
	}

	response, err := c.doRequestWithRetry(ctx, requestURL)
	if err != nil {
		return dto.CVELookupResponse{}, fmt.Errorf("%w: request failed", ErrNVDUnavailable)
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusTooManyRequests:
		return dto.CVELookupResponse{}, ErrNVDRateLimited
	case http.StatusNotFound:
		return dto.CVELookupResponse{}, ErrCVEIDNotFound
	default:
		return dto.CVELookupResponse{}, fmt.Errorf("%w: status %d", ErrNVDUnavailable, response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return dto.CVELookupResponse{}, fmt.Errorf("%w: read response", ErrNVDUnavailable)
	}

	var payload cveAPIResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return dto.CVELookupResponse{}, fmt.Errorf("%w: decode response", ErrInvalidNVDResponse)
	}
	if payload.TotalResults == 0 || len(payload.Vulnerabilities) == 0 {
		return dto.CVELookupResponse{}, ErrCVEIDNotFound
	}

	cve := payload.Vulnerabilities[0].CVE
	if baseservice.NormalizeCVEID(cve.ID) != normalizedCVEID {
		return dto.CVELookupResponse{}, ErrInvalidNVDResponse
	}

	return mapCVE(cve), nil
}

// SearchCVEsByCPE retrieves vulnerable CVE records for an exact NVD CPE name.
func (c *Client) SearchCVEsByCPE(ctx context.Context, cpeName string, limit int) ([]dto.CVELookupResponse, error) {
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
		return []dto.CVELookupResponse{}, nil
	}

	results := make([]dto.CVELookupResponse, 0, min(limit, len(payload.Vulnerabilities)))
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
func (c *Client) SearchCVEsByKeyword(ctx context.Context, keywordSearch string, limit int) ([]dto.CVELookupResponse, error) {
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
		return []dto.CVELookupResponse{}, nil
	}

	results := make([]dto.CVELookupResponse, 0, min(limit, len(payload.Vulnerabilities)))
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

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (c *Client) doRequestWithRetry(ctx context.Context, requestURL string) (*http.Response, error) {
	response, err := c.doRequest(ctx, requestURL)
	if !shouldRetryNVDRequest(response, err) {
		return response, err
	}

	closeResponseBody(response)
	sleep := c.sleep
	if sleep == nil {
		sleep = sleepWithContext
	}
	if err := sleep(ctx, c.retryDelay); err != nil {
		return nil, err
	}

	return c.doRequest(ctx, requestURL)
}

func (c *Client) doRequest(ctx context.Context, requestURL string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request", ErrNVDUnavailable)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "SecureOps backend-go NVD client")
	if c.apiKey != "" {
		request.Header.Set("apiKey", c.apiKey)
	}

	return c.httpClient.Do(request)
}

func shouldRetryNVDRequest(response *http.Response, err error) bool {
	if isRequestTimeout(err) {
		return true
	}
	if response == nil {
		return false
	}

	return response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable
}

func isRequestTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var timeoutErr interface {
		Timeout() bool
	}
	return errors.As(err, &timeoutErr) && timeoutErr.Timeout()
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func closeResponseBody(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
}

func (c *Client) lookupURL(cveID string) (string, error) {
	parsed, err := url.Parse(c.baseURL)
	if err != nil {
		return "", ErrInvalidBaseURL
	}
	values := parsed.Query()
	values.Set("cveIds", cveID)
	parsed.RawQuery = values.Encode()
	return parsed.String(), nil
}

func (c *Client) cpeSearchURL(cpeName string, limit int) (string, error) {
	parsed, err := url.Parse(c.baseURL)
	if err != nil {
		return "", ErrInvalidBaseURL
	}
	values := parsed.Query()
	values.Set("cpeName", cpeName)
	values.Set("isVulnerable", "")
	values.Set("resultsPerPage", fmt.Sprintf("%d", limit))
	parsed.RawQuery = values.Encode()
	return parsed.String(), nil
}

func (c *Client) keywordSearchURL(keywordSearch string, limit int) (string, error) {
	parsed, err := url.Parse(c.baseURL)
	if err != nil {
		return "", ErrInvalidBaseURL
	}
	values := parsed.Query()
	values.Set("keywordSearch", keywordSearch)
	values.Set("resultsPerPage", fmt.Sprintf("%d", limit))
	parsed.RawQuery = strings.ReplaceAll(values.Encode(), "+", "%20")
	return parsed.String(), nil
}

func normalizeCVEKeywordSearch(keywordSearch string) string {
	keywordSearch = strings.TrimSpace(keywordSearch)
	if len(keywordSearch) > 120 {
		return ""
	}

	fields := strings.Fields(keywordSearch)
	if len(fields) == 0 || len(fields) > 8 {
		return ""
	}
	for _, field := range fields {
		if len(field) > 40 {
			return ""
		}
	}

	return strings.Join(fields, " ")
}

func validateBaseURL(baseURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", ErrInvalidBaseURL
	}
	if parsed.Scheme != "https" || parsed.Host != officialNVDHost || parsed.Path != "/rest/json/cves/2.0" {
		return "", ErrInvalidBaseURL
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

type cveAPIResponse struct {
	TotalResults    int                 `json:"totalResults"`
	Vulnerabilities []vulnerabilityItem `json:"vulnerabilities"`
}

type vulnerabilityItem struct {
	CVE cveItem `json:"cve"`
}

type cveItem struct {
	ID                    string        `json:"id"`
	Published             string        `json:"published"`
	LastModified          string        `json:"lastModified"`
	CISAVulnerabilityName string        `json:"cisaVulnerabilityName"`
	Descriptions          []description `json:"descriptions"`
	Metrics               metrics       `json:"metrics"`
}

type description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type metrics struct {
	CVSSMetricV40 []cvssMetricV4 `json:"cvssMetricV40"`
	CVSSMetricV31 []cvssMetricV3 `json:"cvssMetricV31"`
	CVSSMetricV30 []cvssMetricV3 `json:"cvssMetricV30"`
	CVSSMetricV2  []cvssMetricV2 `json:"cvssMetricV2"`
}

type cvssMetricV4 struct {
	CVSSData cvssData `json:"cvssData"`
}

type cvssMetricV3 struct {
	CVSSData cvssData `json:"cvssData"`
}

type cvssMetricV2 struct {
	BaseSeverity string `json:"baseSeverity"`
}

type cvssData struct {
	BaseSeverity string `json:"baseSeverity"`
}

func mapCVE(cve cveItem) dto.CVELookupResponse {
	title := strings.TrimSpace(cve.CISAVulnerabilityName)
	if title == "" {
		title = strings.TrimSpace(cve.ID)
	}

	return dto.CVELookupResponse{
		CVEID:          strings.TrimSpace(cve.ID),
		Title:          title,
		Description:    englishDescription(cve.Descriptions),
		Severity:       severity(cve.Metrics),
		PublishedAt:    strings.TrimSpace(cve.Published),
		LastModifiedAt: strings.TrimSpace(cve.LastModified),
		NVDURL:         "https://nvd.nist.gov/vuln/detail/" + strings.TrimSpace(cve.ID),
	}
}

func englishDescription(descriptions []description) string {
	for _, description := range descriptions {
		if strings.EqualFold(description.Lang, "en") {
			return strings.TrimSpace(description.Value)
		}
	}
	if len(descriptions) == 0 {
		return ""
	}
	return strings.TrimSpace(descriptions[0].Value)
}

func severity(metrics metrics) string {
	if len(metrics.CVSSMetricV40) > 0 && strings.TrimSpace(metrics.CVSSMetricV40[0].CVSSData.BaseSeverity) != "" {
		return strings.TrimSpace(metrics.CVSSMetricV40[0].CVSSData.BaseSeverity)
	}
	if len(metrics.CVSSMetricV31) > 0 && strings.TrimSpace(metrics.CVSSMetricV31[0].CVSSData.BaseSeverity) != "" {
		return strings.TrimSpace(metrics.CVSSMetricV31[0].CVSSData.BaseSeverity)
	}
	if len(metrics.CVSSMetricV30) > 0 && strings.TrimSpace(metrics.CVSSMetricV30[0].CVSSData.BaseSeverity) != "" {
		return strings.TrimSpace(metrics.CVSSMetricV30[0].CVSSData.BaseSeverity)
	}
	if len(metrics.CVSSMetricV2) > 0 && strings.TrimSpace(metrics.CVSSMetricV2[0].BaseSeverity) != "" {
		return strings.TrimSpace(metrics.CVSSMetricV2[0].BaseSeverity)
	}
	return "UNKNOWN"
}

// RateLimiter limits outbound NVD requests in a rolling window.
type RateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	requests []time.Time
}

// NewRateLimiter creates a rolling-window limiter.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	if limit <= 0 {
		limit = 1
	}
	if window <= 0 {
		window = 30 * time.Second
	}
	return &RateLimiter{limit: limit, window: window}
}

// Allow records a request when capacity remains in the rolling window.
func (r *RateLimiter) Allow(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := now.Add(-r.window)
	kept := r.requests[:0]
	for _, requestTime := range r.requests {
		if requestTime.After(cutoff) {
			kept = append(kept, requestTime)
		}
	}
	r.requests = kept

	if len(r.requests) >= r.limit {
		return false
	}
	r.requests = append(r.requests, now)
	return true
}
