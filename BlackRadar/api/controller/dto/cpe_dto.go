// Package dto defines request and response data transfer objects for the API.
package dto

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

// AssetMatchAnalysisResponse describes the backend-generated match result.
type AssetMatchAnalysisResponse struct {
	ProductFingerprint string         `json:"productFingerprint"`
	KeywordSearch      string         `json:"keywordSearch"`
	SelectedCPE        string         `json:"selectedCpe,omitempty"`
	Confidence         float64        `json:"confidence"`
	ReviewStatus       string         `json:"reviewStatus"`
	ReviewNotes        string         `json:"reviewNotes,omitempty"`
	CandidateCount     int            `json:"candidateCount"`
	Candidates         []CPECandidate `json:"candidates,omitempty"`
}
