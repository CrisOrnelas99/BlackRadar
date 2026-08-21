// Package controller dto defines asset request and response contracts.
package controller

import (
	"strings"
	"time"

	vulnerabilitycontroller "blackradar/api/controller/vulnerability"
	nvdcpeclient "blackradar/api/external/nvd_cpe"
	"blackradar/api/model"
	assetmatchservice "blackradar/api/service/asset_match"
)

// AssetRequest describes the writable asset fields accepted by the API.
type AssetRequest struct {
	Name            string  `json:"name"`
	Type            string  `json:"type"`
	Description     *string `json:"description,omitempty"`
	OperatingSystem *string `json:"operatingSystem"`
	Vendor          *string `json:"vendor,omitempty"`
	Product         *string `json:"product,omitempty"`
	Version         *string `json:"version,omitempty"`
	DeviceModel     *string `json:"deviceModel,omitempty"`
	Owner           string  `json:"owner"`
	Criticality     string  `json:"criticality"`
}

// ToDataModel converts the request into the persistence model with trimmed values.
func (r AssetRequest) ToDataModel() model.Asset {
	operatingSystem := trimOptionalString(r.OperatingSystem)

	return model.Asset{
		Name:            strings.TrimSpace(r.Name),
		Type:            strings.TrimSpace(r.Type),
		Description:     trimOptionalString(r.Description),
		OperatingSystem: operatingSystem,
		Vendor:          trimOptionalString(r.Vendor),
		Product:         trimOptionalString(r.Product),
		Version:         trimOptionalString(r.Version),
		DeviceModel:     trimOptionalString(r.DeviceModel),
		Owner:           strings.TrimSpace(r.Owner),
		Criticality:     strings.TrimSpace(r.Criticality),
		RiskLevel:       nil,
	}
}

// AssetResponse exposes the public asset fields returned by the API.
type AssetResponse struct {
	ID                 string    `json:"id"`
	AssetAssessmentID  *string   `json:"assetAssessmentId,omitempty"`
	Name               string    `json:"name"`
	Type               string    `json:"type"`
	Description        *string   `json:"description,omitempty"`
	OperatingSystem    *string   `json:"operatingSystem"`
	Vendor             *string   `json:"vendor,omitempty"`
	Product            *string   `json:"product,omitempty"`
	Version            *string   `json:"version,omitempty"`
	Owner              string    `json:"owner"`
	Criticality        string    `json:"criticality"`
	RiskLevel          *string   `json:"riskLevel"`
	VulnerabilityCount int       `json:"vulnerabilityCount"`
	CreatedAt          time.Time `json:"createdAt"`
	UpdatedAt          time.Time `json:"updatedAt"`
}

// AssetWithVulnerabilitiesResponse exposes the minimal asset shape with attached vulnerabilities.
type AssetWithVulnerabilitiesResponse struct {
	AssetResponse
	Vulnerabilities []vulnerabilitycontroller.VulnerabilityResponse `json:"vulnerabilities,omitempty"`
}

// AssetAssessmentResponse exposes the linked asset assessment metadata separately from the asset record.
type AssetAssessmentResponse struct {
	ID                 *string    `json:"id,omitempty"`
	RiskScore          int16      `json:"riskScore"`
	ProductFingerprint *string    `json:"productFingerprint,omitempty"`
	SelectedCPE        *string    `json:"selectedCpe,omitempty"`
	CPEConfidence      *float64   `json:"cpeConfidence,omitempty"`
	CPEReviewStatus    string     `json:"cpeReviewStatus"`
	CPEReviewNotes     *string    `json:"cpeReviewNotes,omitempty"`
	CPECandidateCount  int        `json:"cpeCandidateCount"`
	CPEMatchedAt       *time.Time `json:"cpeMatchedAt,omitempty"`
	CreatedAt          *time.Time `json:"createdAt,omitempty"`
	UpdatedAt          *time.Time `json:"updatedAt,omitempty"`
}

// AssetMatchResponse returns the asset and linked assessment separately for match-oriented workflows.
type AssetMatchResponse struct {
	Asset           AssetWithVulnerabilitiesResponse `json:"asset"`
	AssetAssessment AssetAssessmentResponse          `json:"assetAssessment"`
}

// AssetMatchPreviewResponse exposes a non-persistent, AI-assisted CPE proposal for review.
type AssetMatchPreviewResponse struct {
	ProductFingerprint string                 `json:"productFingerprint"`
	SelectedCPE        string                 `json:"selectedCpe,omitempty"`
	CVECount           int                    `json:"cveCount"`
	CVEIDs             []string               `json:"cveIds"`
	CVEDataAvailable   bool                   `json:"cveDataAvailable"`
	Confidence         float64                `json:"confidence,omitempty"`
	ReviewStatus       string                 `json:"reviewStatus"`
	ReviewNotes        string                 `json:"reviewNotes,omitempty"`
	CandidateCount     int                    `json:"candidateCount"`
	Candidates         []CPECandidateResponse `json:"candidates"`
}

// CPECandidateResponse exposes one NVD CPE candidate that an administrator can approve.
type CPECandidateResponse struct {
	CPEName string `json:"cpeName"`
	Title   string `json:"title"`
}

// ApplyAssetMatchRequest identifies the NVD CPE explicitly approved for persistence.
type ApplyAssetMatchRequest struct {
	SelectedCPE string `json:"selectedCpe"`
}

// PreviewAssetMatchRequest optionally selects one CPE candidate for CVE counting.
type PreviewAssetMatchRequest struct {
	SelectedCPE string `json:"selectedCpe"`
}

// ToAssetResponseDTO converts an asset model into its response DTO.
func ToAssetResponseDTO(asset model.Asset) AssetResponse {
	return AssetResponse{
		ID:                 asset.ID,
		AssetAssessmentID:  asset.AssetAssessmentID,
		Name:               asset.Name,
		Type:               asset.Type,
		Description:        asset.Description,
		OperatingSystem:    asset.OperatingSystem,
		Vendor:             asset.Vendor,
		Product:            asset.Product,
		Version:            asset.Version,
		Owner:              asset.Owner,
		Criticality:        asset.Criticality,
		RiskLevel:          asset.RiskLevel,
		VulnerabilityCount: asset.VulnerabilityCount,
		CreatedAt:          asset.CreatedAt,
		UpdatedAt:          asset.UpdatedAt,
	}
}

// ToAssetResponseDTOs converts multiple asset models into response DTOs.
func ToAssetResponseDTOs(assets []model.Asset) []AssetResponse {
	result := make([]AssetResponse, 0, len(assets))
	for _, asset := range assets {
		result = append(result, ToAssetResponseDTO(asset))
	}
	return result
}

// ToAssetWithVulnerabilitiesResponseDTO converts an asset into the minimal asset response plus vulnerability details.
func ToAssetWithVulnerabilitiesResponseDTO(asset model.Asset) AssetWithVulnerabilitiesResponse {
	return AssetWithVulnerabilitiesResponse{
		AssetResponse:   ToAssetResponseDTO(asset),
		Vulnerabilities: vulnerabilitycontroller.ToVulnerabilityResponseDTOs(asset.Vulnerabilities),
	}
}

// ToAssetAssessmentResponseDTO converts an asset's linked assessment into its response DTO.
func ToAssetAssessmentResponseDTO(asset model.Asset) AssetAssessmentResponse {
	response := AssetAssessmentResponse{
		ID:              asset.AssetAssessmentID,
		RiskScore:       0,
		CPEReviewStatus: model.AssetCPEReviewStatusNeedsReview,
	}

	if asset.Assessment == nil {
		return response
	}

	if response.ID == nil {
		response.ID = &asset.Assessment.ID
	}
	response.RiskScore = asset.Assessment.RiskScore
	response.ProductFingerprint = asset.Assessment.ProductFingerprint
	response.SelectedCPE = asset.Assessment.SelectedCPE
	response.CPEConfidence = asset.Assessment.CPEConfidence
	response.CPEReviewNotes = asset.Assessment.CPEReviewNotes
	response.CPECandidateCount = asset.Assessment.CPECandidateCount
	response.CPEMatchedAt = asset.Assessment.CPEMatchedAt
	response.CreatedAt = &asset.Assessment.CreatedAt
	response.UpdatedAt = &asset.Assessment.UpdatedAt
	if asset.Assessment.CPEReviewStatus != "" {
		response.CPEReviewStatus = asset.Assessment.CPEReviewStatus
	}

	return response
}

// ToAssetMatchResponseDTO converts an asset into the separated match workflow response shape.
func ToAssetMatchResponseDTO(asset model.Asset) AssetMatchResponse {
	return AssetMatchResponse{
		Asset:           ToAssetWithVulnerabilitiesResponseDTO(asset),
		AssetAssessment: ToAssetAssessmentResponseDTO(asset),
	}
}

// ToAssetMatchPreviewResponseDTO converts a non-persistent analysis into its HTTP response.
func ToAssetMatchPreviewResponseDTO(preview assetmatchservice.AssetMatchPreview) AssetMatchPreviewResponse {
	analysis := preview.Analysis
	cveIDs := preview.CVEIDs
	if cveIDs == nil {
		cveIDs = []string{}
	}

	return AssetMatchPreviewResponse{
		ProductFingerprint: analysis.ProductFingerprint,
		SelectedCPE:        analysis.SelectedCPE,
		CVECount:           preview.CVECount,
		CVEIDs:             cveIDs,
		CVEDataAvailable:   preview.CVEDataAvailable,
		Confidence:         analysis.Confidence,
		ReviewStatus:       analysis.ReviewStatus,
		ReviewNotes:        analysis.ReviewNotes,
		CandidateCount:     analysis.CandidateCount,
		Candidates:         toCPECandidateResponseDTOs(analysis.Candidates),
	}
}

func toCPECandidateResponseDTOs(candidates []nvdcpeclient.CPECandidate) []CPECandidateResponse {
	response := make([]CPECandidateResponse, 0, len(candidates))
	for _, candidate := range candidates {
		response = append(response, CPECandidateResponse{CPEName: candidate.CPEName, Title: candidate.Title})
	}
	return response
}

// trimOptionalString trims optional request text and preserves nil for empty values.
func trimOptionalString(value *string) *string {
	if value == nil {
		return nil
	}

	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}

	return &trimmed
}
