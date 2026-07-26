// Package cpeclient dto defines CPE request and response contracts used by services.
package cpeclient

// CPEMatchRequest describes the normalized search terms used for NVD CPE lookup.
type CPEMatchRequest struct {
	KeywordSearch string `json:"keywordSearch"`
}

// CPECandidate represents one NVD CPE candidate returned by the backend.
type CPECandidate struct {
	CPEName    string `json:"cpeName"`
	Title      string `json:"title"`
	Deprecated bool   `json:"deprecated"`
}
