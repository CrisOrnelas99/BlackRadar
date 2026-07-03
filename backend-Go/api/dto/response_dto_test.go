// Package dto tests response DTO mapping behavior.
package dto

import (
	"testing"
	"time"

	"secureops/backend-go/api/model"
)

func stringPtr(value string) *string {
	return &value
}

func TestToAssetResponseDTOIncludesMatchMetadata(t *testing.T) {
	assessmentID := int64(55)
	matchedAt := time.Date(2026, time.January, 12, 10, 30, 0, 0, time.UTC)
	productFingerprint := "vendor=dell;product=latitude 7420;version=1.2"
	selectedCPE := "cpe:2.3:a:dell:latitude_7420:1.2:*:*:*:*:*:*:*"
	confidence := 0.91
	reviewNotes := "strong vendor/product/version match"
	riskScore := int16(72)

	response := ToAssetResponseDTO(model.Asset{
		ID:                7,
		AssetAssessmentID: &assessmentID,
		Name:              "Asset 1",
		Type:              "Server",
		Owner:             "IT",
		Criticality:       "High",
		RiskLevel:         nil,
		Assessment: &model.AssetAssessment{
			RiskScore:          riskScore,
			ProductFingerprint: &productFingerprint,
			SelectedCPE:        &selectedCPE,
			CPEConfidence:      &confidence,
			CPEReviewNotes:     &reviewNotes,
			CPECandidateCount:  4,
			CPEMatchedAt:       &matchedAt,
		},
	})

	if response.AssetAssessmentID == nil || *response.AssetAssessmentID != assessmentID {
		t.Fatalf("expected asset assessment id %d, got %#v", assessmentID, response.AssetAssessmentID)
	}
	if response.RiskLevel != nil {
		t.Fatalf("expected risk level to be null, got %#v", response.RiskLevel)
	}
}

func TestToAssetMatchResponseDTOSeparatesAssessmentMetadata(t *testing.T) {
	assessmentID := int64(55)
	matchedAt := time.Date(2026, time.January, 12, 10, 30, 0, 0, time.UTC)
	productFingerprint := "vendor=dell;product=latitude 7420;version=1.2"
	selectedCPE := "cpe:2.3:a:dell:latitude_7420:1.2:*:*:*:*:*:*:*"
	confidence := 0.91
	reviewNotes := "strong vendor/product/version match"
	riskScore := int16(72)
	assessmentCreatedAt := time.Date(2026, time.January, 11, 10, 30, 0, 0, time.UTC)
	assessmentUpdatedAt := time.Date(2026, time.January, 12, 10, 31, 0, 0, time.UTC)

	response := ToAssetMatchResponseDTO(model.Asset{
		ID:                7,
		AssetAssessmentID: &assessmentID,
		Name:              "Asset 1",
		Type:              "Server",
		Owner:             "IT",
		Criticality:       "High",
		RiskLevel:         stringPtr("Critical"),
		Vulnerabilities: []model.Vulnerability{
			{ID: 9, CVEID: "CVE-2026-0001", Title: "Issue", Severity: "High", Description: "desc", Status: "Open"},
		},
		Assessment: &model.AssetAssessment{
			ID:                 assessmentID,
			RiskScore:          riskScore,
			ProductFingerprint: &productFingerprint,
			SelectedCPE:        &selectedCPE,
			CPEConfidence:      &confidence,
			CPEReviewNotes:     &reviewNotes,
			CPECandidateCount:  4,
			CPEMatchedAt:       &matchedAt,
			CreatedAt:          assessmentCreatedAt,
			UpdatedAt:          assessmentUpdatedAt,
		},
	})

	if response.Asset.AssetAssessmentID == nil || *response.Asset.AssetAssessmentID != assessmentID {
		t.Fatalf("expected nested asset assessment id %d, got %#v", assessmentID, response.Asset.AssetAssessmentID)
	}
	if len(response.Asset.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(response.Asset.Vulnerabilities))
	}
	if response.Asset.RiskLevel == nil || *response.Asset.RiskLevel != "Critical" {
		t.Fatalf("expected nested asset risk level Critical, got %#v", response.Asset.RiskLevel)
	}
	if response.AssetAssessment.ID == nil || *response.AssetAssessment.ID != assessmentID {
		t.Fatalf("expected assessment id %d, got %#v", assessmentID, response.AssetAssessment.ID)
	}
	if response.AssetAssessment.CPEReviewStatus != model.AssetCPEReviewStatusNeedsReview {
		t.Fatalf("expected default review status %q, got %q", model.AssetCPEReviewStatusNeedsReview, response.AssetAssessment.CPEReviewStatus)
	}
	if response.AssetAssessment.RiskScore != riskScore {
		t.Fatalf("expected risk score %d, got %d", riskScore, response.AssetAssessment.RiskScore)
	}
	if response.AssetAssessment.ProductFingerprint == nil || *response.AssetAssessment.ProductFingerprint != productFingerprint {
		t.Fatalf("expected product fingerprint %q, got %#v", productFingerprint, response.AssetAssessment.ProductFingerprint)
	}
	if response.AssetAssessment.SelectedCPE == nil || *response.AssetAssessment.SelectedCPE != selectedCPE {
		t.Fatalf("expected selected CPE %q, got %#v", selectedCPE, response.AssetAssessment.SelectedCPE)
	}
	if response.AssetAssessment.CPEConfidence == nil || *response.AssetAssessment.CPEConfidence != confidence {
		t.Fatalf("expected confidence %v, got %#v", confidence, response.AssetAssessment.CPEConfidence)
	}
	if response.AssetAssessment.CPEReviewNotes == nil || *response.AssetAssessment.CPEReviewNotes != reviewNotes {
		t.Fatalf("expected review notes %q, got %#v", reviewNotes, response.AssetAssessment.CPEReviewNotes)
	}
	if response.AssetAssessment.CPECandidateCount != 4 {
		t.Fatalf("expected candidate count 4, got %d", response.AssetAssessment.CPECandidateCount)
	}
	if response.AssetAssessment.CPEMatchedAt == nil || !response.AssetAssessment.CPEMatchedAt.Equal(matchedAt) {
		t.Fatalf("expected matched at %v, got %#v", matchedAt, response.AssetAssessment.CPEMatchedAt)
	}
	if response.AssetAssessment.CreatedAt == nil || !response.AssetAssessment.CreatedAt.Equal(assessmentCreatedAt) {
		t.Fatalf("expected assessment created at %v, got %#v", assessmentCreatedAt, response.AssetAssessment.CreatedAt)
	}
	if response.AssetAssessment.UpdatedAt == nil || !response.AssetAssessment.UpdatedAt.Equal(assessmentUpdatedAt) {
		t.Fatalf("expected assessment updated at %v, got %#v", assessmentUpdatedAt, response.AssetAssessment.UpdatedAt)
	}
}

func TestToAssetAssessmentResponseDTODefaultsWithoutAssessment(t *testing.T) {
	assessmentID := int64(77)
	response := ToAssetAssessmentResponseDTO(model.Asset{
		AssetAssessmentID: &assessmentID,
	})

	if response.ID == nil || *response.ID != assessmentID {
		t.Fatalf("expected assessment id %d, got %#v", assessmentID, response.ID)
	}
	if response.RiskScore != 0 {
		t.Fatalf("expected default risk score 0, got %d", response.RiskScore)
	}
	if response.CPEReviewStatus != model.AssetCPEReviewStatusNeedsReview {
		t.Fatalf("expected default review status %q, got %q", model.AssetCPEReviewStatusNeedsReview, response.CPEReviewStatus)
	}
}
