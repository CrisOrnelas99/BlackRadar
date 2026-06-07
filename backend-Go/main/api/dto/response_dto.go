package dto

import (
	"time"

	"secureops/backend-go/api/model"
)

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

type AssetResponse struct {
	ID              int64                   `json:"id"`
	Name            string                  `json:"name"`
	Type            string                  `json:"type"`
	IPAddress       string                  `json:"ipAddress"`
	OperatingSystem *string                 `json:"operatingSystem"`
	Owner           string                  `json:"owner"`
	Criticality     string                  `json:"criticality"`
	RiskScore       int16                   `json:"riskScore"`
	RiskLevel       string                  `json:"riskLevel"`
	Vulnerabilities []VulnerabilityResponse `json:"vulnerabilities,omitempty"`
	CreatedAt       time.Time               `json:"createdAt"`
	UpdatedAt       time.Time               `json:"updatedAt"`
}

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

func ToVulnerabilityResponseDTOs(vulnerabilities []model.Vulnerability) []VulnerabilityResponse {
	result := make([]VulnerabilityResponse, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		result = append(result, ToVulnerabilityResponseDTO(vulnerability))
	}
	return result
}

func ToAssetResponseDTO(asset model.Asset) AssetResponse {
	return AssetResponse{
		ID:              asset.ID,
		Name:            asset.Name,
		Type:            asset.Type,
		IPAddress:       asset.IPAddress,
		OperatingSystem: asset.OperatingSystem,
		Owner:           asset.Owner,
		Criticality:     asset.Criticality,
		RiskScore:       asset.RiskScore,
		RiskLevel:       asset.RiskLevel,
		Vulnerabilities: ToVulnerabilityResponseDTOs(asset.Vulnerabilities),
		CreatedAt:       asset.CreatedAt,
		UpdatedAt:       asset.UpdatedAt,
	}
}

func ToAssetResponseDTOs(assets []model.Asset) []AssetResponse {
	result := make([]AssetResponse, 0, len(assets))
	for _, asset := range assets {
		result = append(result, ToAssetResponseDTO(asset))
	}
	return result
}
