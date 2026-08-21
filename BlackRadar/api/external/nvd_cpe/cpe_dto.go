// Package cpeclient dto defines CPE request and response contracts used by services.
package cpeclient

// CPEMatchRequest describes one backend-generated NVD CPE lookup.
type CPEMatchRequest struct {
	CPEMatchString string `json:"cpeMatchString,omitempty"`
	KeywordSearch  string `json:"keywordSearch,omitempty"`
}

// CPECandidate represents one NVD CPE candidate returned by the backend.
type CPECandidate struct {
	CPEName    string `json:"cpeName"`
	Title      string `json:"title"`
	Deprecated bool   `json:"deprecated"`
}
