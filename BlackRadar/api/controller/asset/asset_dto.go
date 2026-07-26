// Package controller dto defines asset request and response contracts.
package controller

import (
	"strings"
	"time"

	vulnerabilitycontroller "blackradar/api/controller/vulnerability"
	"blackradar/api/model"
)

// AssetRequest describes the writable asset fields accepted by the API.
type AssetRequest struct {
	Name            string  `json:"name"`
	Type            string  `json:"type"`
	OperatingSystem *string `json:"operatingSystem"`
	Vendor          *string `json:"vendor,omitempty"`
	Product         *string `json:"product,omitempty"`
	Version         *string `json:"version,omitempty"`
	DeviceModel     *string `json:"deviceModel,omitempty"`
	Owner           string  `json:"owner"`
	Criticality     string  `json:"criticality"`
	AIMode          bool    `json:"aiMode,omitempty"`
	RawText         string  `json:"rawText,omitempty"`
}

// ToDataModel converts the request into the persistence model with trimmed values.
func (r AssetRequest) ToDataModel() model.Asset {
	operatingSystem := trimOptionalString(r.OperatingSystem)

	return model.Asset{
		Name:            strings.TrimSpace(r.Name),
		Type:            strings.TrimSpace(r.Type),
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
