// Package cveclient support handles NVD CVE request construction, validation,
// retry behavior, and response mapping.
package cveclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// newHTTPClient creates the production HTTP client used for NVD API calls.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// doRequestWithRetry retries one transient NVD request failure before returning.
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

// doRequest builds and executes a single authenticated NVD GET request.
func (c *Client) doRequest(ctx context.Context, requestURL string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request", ErrNVDUnavailable)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "BlackRadar API NVD client")
	if c.apiKey != "" {
		request.Header.Set("apiKey", c.apiKey)
	}

	return c.httpClient.Do(request)
}

// shouldRetryNVDRequest reports whether an NVD response or error is transient.
func shouldRetryNVDRequest(response *http.Response, err error) bool {
	if isRequestTimeout(err) {
		return true
	}
	if response == nil {
		return false
	}

	return response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable
}

// isRequestTimeout reports whether an error represents a request timeout.
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

// sleepWithContext waits for a retry delay while respecting context cancellation.
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

// closeResponseBody closes a retry response body when one was returned.
func closeResponseBody(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
}

// lookupURL builds an NVD CVE lookup URL for a normalized CVE identifier.
func (c *Client) lookupURL(cveID string) (string, error) {
	parsed, err := url.Parse(c.baseURL)
	if err != nil {
		return "", ErrInvalidNVDBaseURL
	}
	values := parsed.Query()
	values.Set("cveIds", cveID)
	parsed.RawQuery = values.Encode()
	return parsed.String(), nil
}

// cpeSearchURL builds an NVD CVE search URL for an exact vulnerable CPE name.
func (c *Client) cpeSearchURL(cpeName string, limit int) (string, error) {
	parsed, err := url.Parse(c.baseURL)
	if err != nil {
		return "", ErrInvalidNVDBaseURL
	}
	values := parsed.Query()
	values.Set("cpeName", cpeName)
	values.Set("isVulnerable", "")
	values.Set("resultsPerPage", fmt.Sprintf("%d", limit))
	parsed.RawQuery = values.Encode()
	return parsed.String(), nil
}

// keywordSearchURL builds an NVD CVE search URL for a bounded keyword search.
func (c *Client) keywordSearchURL(keywordSearch string, limit int) (string, error) {
	parsed, err := url.Parse(c.baseURL)
	if err != nil {
		return "", ErrInvalidNVDBaseURL
	}
	values := parsed.Query()
	values.Set("keywordSearch", keywordSearch)
	values.Set("resultsPerPage", fmt.Sprintf("%d", limit))
	parsed.RawQuery = strings.ReplaceAll(values.Encode(), "+", "%20")
	return parsed.String(), nil
}

// normalizeCVEKeywordSearch trims and bounds backend-generated NVD keyword searches.
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

// validateBaseURL validates and normalizes the official NVD CVE API endpoint.
func validateBaseURL(baseURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", ErrInvalidNVDBaseURL
	}
	if parsed.Scheme != "https" || parsed.Host != officialNVDHost || parsed.Path != "/rest/json/cves/2.0" {
		return "", ErrInvalidNVDBaseURL
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

// normalizeCVEID trims and uppercases a CVE identifier before lookup.
func normalizeCVEID(cveID string) string {
	return strings.ToUpper(strings.TrimSpace(cveID))
}

// validateCVEID verifies the identifier is safe to use with the NVD CVE API.
func validateCVEID(cveID string) error {
	if !cveIDPattern.MatchString(normalizeCVEID(cveID)) {
		return ErrInvalidCVEID
	}
	return nil
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
	CVSSMetricV40 []cvssMetric `json:"cvssMetricV40"`
	CVSSMetricV31 []cvssMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []cvssMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []cvssMetric `json:"cvssMetricV2"`
}

type cvssMetric struct {
	CVSSData     cvssData `json:"cvssData"`
	BaseSeverity string   `json:"baseSeverity"`
}

type cvssData struct {
	BaseSeverity string `json:"baseSeverity"`
}

// mapCVE converts an NVD CVE item into the application's lookup response DTO.
func mapCVE(cve cveItem) CVELookupResponse {
	title := strings.TrimSpace(cve.CISAVulnerabilityName)
	if title == "" {
		title = strings.TrimSpace(cve.ID)
	}

	return CVELookupResponse{
		CVEID:          strings.TrimSpace(cve.ID),
		Title:          title,
		Description:    englishDescription(cve.Descriptions),
		Severity:       severity(cve.Metrics),
		PublishedAt:    strings.TrimSpace(cve.Published),
		LastModifiedAt: strings.TrimSpace(cve.LastModified),
		NVDURL:         "https://nvd.nist.gov/vuln/detail/" + strings.TrimSpace(cve.ID),
	}
}

// englishDescription returns the English CVE description when available.
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

// severity returns the best available CVSS severity across supported metric versions.
func severity(metrics metrics) string {
	for _, candidates := range [][]cvssMetric{
		metrics.CVSSMetricV40,
		metrics.CVSSMetricV31,
		metrics.CVSSMetricV30,
		metrics.CVSSMetricV2,
	} {
		if value := firstSeverity(candidates); value != "" {
			return value
		}
	}
	return "UNKNOWN"
}

// firstSeverity returns the first populated severity from a CVSS metric list.
func firstSeverity(metrics []cvssMetric) string {
	if len(metrics) == 0 {
		return ""
	}
	if value := strings.TrimSpace(metrics[0].CVSSData.BaseSeverity); value != "" {
		return value
	}
	return strings.TrimSpace(metrics[0].BaseSeverity)
}
