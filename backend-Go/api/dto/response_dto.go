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
	ID          int64     `json:"id"`
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
	ID                 int64                   `json:"id"`
	Name               string                  `json:"name"`
	Type               string                  `json:"type"`
	OperatingSystem    *string                 `json:"operatingSystem"`
	Vendor             *string                 `json:"vendor,omitempty"`
	Product            *string                 `json:"product,omitempty"`
	Version            *string                 `json:"version,omitempty"`
	DeviceModel        *string                 `json:"deviceModel,omitempty"`
	Owner              string                  `json:"owner"`
	Criticality        string                  `json:"criticality"`
	RiskScore          int16                   `json:"riskScore"`
	RiskLevel          string                  `json:"riskLevel"`
	ProductFingerprint *string                 `json:"productFingerprint,omitempty"`
	SelectedCPE        *string                 `json:"selectedCpe,omitempty"`
	CPEConfidence      *float64                `json:"cpeConfidence,omitempty"`
	CPEReviewStatus    string                  `json:"cpeReviewStatus"`
	CPEReviewNotes     *string                 `json:"cpeReviewNotes,omitempty"`
	CPECandidateCount  int                     `json:"cpeCandidateCount"`
	CPEMatchedAt       *time.Time              `json:"cpeMatchedAt,omitempty"`
	Vulnerabilities    []VulnerabilityResponse `json:"vulnerabilities,omitempty"`
	CreatedAt          time.Time               `json:"createdAt"`
	UpdatedAt          time.Time               `json:"updatedAt"`
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
	reviewStatus := asset.CPEReviewStatus
	if reviewStatus == "" {
		reviewStatus = model.AssetCPEReviewStatusNeedsReview
	}

	return AssetResponse{
		ID:                 asset.ID,
		Name:               asset.Name,
		Type:               asset.Type,
		OperatingSystem:    asset.OperatingSystem,
		Vendor:             asset.Vendor,
		Product:            asset.Product,
		Version:            asset.Version,
		DeviceModel:        asset.DeviceModel,
		Owner:              asset.Owner,
		Criticality:        asset.Criticality,
		RiskScore:          asset.RiskScore,
		RiskLevel:          asset.RiskLevel,
		ProductFingerprint: asset.ProductFingerprint,
		SelectedCPE:        asset.SelectedCPE,
		CPEConfidence:      asset.CPEConfidence,
		CPEReviewStatus:    reviewStatus,
		CPEReviewNotes:     asset.CPEReviewNotes,
		CPECandidateCount:  asset.CPECandidateCount,
		CPEMatchedAt:       asset.CPEMatchedAt,
		Vulnerabilities:    ToVulnerabilityResponseDTOs(asset.Vulnerabilities),
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
