// Package dto defines request and response data transfer objects for the API.
package dto

import (
	"time"

	"secureops/backend-go/api/model"
)

// ErrorResponse is the safe error envelope returned to API clients.
type ErrorResponse struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"requestId"`
}

// VulnerabilityResponse exposes the public vulnerability fields returned by the API.
type VulnerabilityResponse struct {
	ID          string    `json:"id"`
	CVEID       string    `json:"cveId"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// AssetResponse exposes the public asset fields returned by the API.
type AssetResponse struct {
	ID                string    `json:"id"`
	AssetAssessmentID *string   `json:"assetAssessmentId,omitempty"`
	Name              string    `json:"name"`
	Type              string    `json:"type"`
	OperatingSystem   *string   `json:"operatingSystem"`
	Vendor            *string   `json:"vendor,omitempty"`
	Product           *string   `json:"product,omitempty"`
	Version           *string   `json:"version,omitempty"`
	Owner             string    `json:"owner"`
	Criticality       string    `json:"criticality"`
	RiskLevel         *string   `json:"riskLevel"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

// AssetWithVulnerabilitiesResponse exposes the minimal asset shape with attached vulnerabilities.
type AssetWithVulnerabilitiesResponse struct {
	AssetResponse
	Vulnerabilities []VulnerabilityResponse `json:"vulnerabilities,omitempty"`
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

// ToVulnerabilityResponseDTO converts a vulnerability model into its response DTO.
func ToVulnerabilityResponseDTO(vulnerability model.Vulnerability) VulnerabilityResponse {
	return VulnerabilityResponse{
		ID:          vulnerability.ID,
		CVEID:       vulnerability.CVEID,
		Title:       vulnerability.Title,
		Severity:    vulnerability.Severity,
		Description: vulnerability.Description,
		Status:      vulnerability.Status,
		CreatedAt:   vulnerability.CreatedAt,
		UpdatedAt:   vulnerability.UpdatedAt,
	}
}

// ToVulnerabilityResponseDTOs converts multiple vulnerability models into response DTOs.
func ToVulnerabilityResponseDTOs(vulnerabilities []model.Vulnerability) []VulnerabilityResponse {
	result := make([]VulnerabilityResponse, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		result = append(result, ToVulnerabilityResponseDTO(vulnerability))
	}
	return result
}

// ToAssetResponseDTO converts an asset model into its response DTO.
func ToAssetResponseDTO(asset model.Asset) AssetResponse {
	return AssetResponse{
		ID:                asset.ID,
		AssetAssessmentID: asset.AssetAssessmentID,
		Name:              asset.Name,
		Type:              asset.Type,
		OperatingSystem:   asset.OperatingSystem,
		Vendor:            asset.Vendor,
		Product:           asset.Product,
		Version:           asset.Version,
		Owner:             asset.Owner,
		Criticality:       asset.Criticality,
		RiskLevel:         asset.RiskLevel,
		CreatedAt:         asset.CreatedAt,
		UpdatedAt:         asset.UpdatedAt,
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
		Vulnerabilities: ToVulnerabilityResponseDTOs(asset.Vulnerabilities),
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
