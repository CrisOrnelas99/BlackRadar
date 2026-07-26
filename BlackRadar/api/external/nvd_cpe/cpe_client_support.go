package cpeclient

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

// newHTTPClient creates the production HTTP client used for CPE API calls.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// searchURL builds a CPE API request URL for the supplied keyword search.
func (c *CPEClient) searchURL(keywordSearch string) (string, error) {
	parsed, err := url.Parse(c.baseURL)
	if err != nil {
		return "", ErrInvalidNVDBaseURL
	}
	values := parsed.Query()
	values.Set("keywordSearch", keywordSearch)
	parsed.RawQuery = values.Encode()
	return parsed.String(), nil
}

// validateCPEBaseURL validates and normalizes the allowed CPE API endpoint.
func validateCPEBaseURL(baseURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", ErrInvalidNVDBaseURL
	}
	if parsed.Path != "/rest/json/cpes/2.0" {
		return "", ErrInvalidNVDBaseURL
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
	return "", ErrInvalidNVDBaseURL
}

// normalizeCPEKeywordSearch trims and bounds backend-generated NVD CPE searches.
func normalizeCPEKeywordSearch(keywordSearch string) string {
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

// isLocalHost reports whether a host is allowed for local test wiring.
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

// mapCPECandidate converts an NVD CPE item into the application's candidate DTO.
func mapCPECandidate(cpe cpeItem) CPECandidate {
	title := cpe.CPEName
	for _, entry := range cpe.Titles {
		if strings.EqualFold(entry.Lang, "en") && strings.TrimSpace(entry.Title) != "" {
			title = strings.TrimSpace(entry.Title)
			break
		}
	}

	return CPECandidate{
		CPEName:    strings.TrimSpace(cpe.CPEName),
		Title:      title,
		Deprecated: cpe.Deprecated,
	}
}
