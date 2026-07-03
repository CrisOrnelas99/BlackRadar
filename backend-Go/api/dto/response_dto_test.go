// Package dto tests response DTO mapping behavior.
package dto

import (
	"testing"
	"time"

	"secureops/backend-go/api/model"
)

func TestToAssetResponseDTOIncludesMatchMetadata(t *testing.T) {
	matchedAt := time.Date(2026, time.January, 12, 10, 30, 0, 0, time.UTC)
	productFingerprint := "vendor=dell;product=latitude 7420;version=1.2"
	selectedCPE := "cpe:2.3:a:dell:latitude_7420:1.2:*:*:*:*:*:*:*"
	confidence := 0.91
	reviewNotes := "strong vendor/product/version match"

	response := ToAssetResponseDTO(model.Asset{
		ProductFingerprint: &productFingerprint,
		SelectedCPE:        &selectedCPE,
		CPEConfidence:      &confidence,
		CPEReviewNotes:     &reviewNotes,
		CPECandidateCount:  4,
		CPEMatchedAt:       &matchedAt,
	})

	if response.CPEReviewStatus != model.AssetCPEReviewStatusNeedsReview {
		t.Fatalf("expected default review status %q, got %q", model.AssetCPEReviewStatusNeedsReview, response.CPEReviewStatus)
	}
	if response.ProductFingerprint == nil || *response.ProductFingerprint != productFingerprint {
		t.Fatalf("expected product fingerprint %q, got %#v", productFingerprint, response.ProductFingerprint)
	}
	if response.SelectedCPE == nil || *response.SelectedCPE != selectedCPE {
		t.Fatalf("expected selected CPE %q, got %#v", selectedCPE, response.SelectedCPE)
	}
	if response.CPEConfidence == nil || *response.CPEConfidence != confidence {
		t.Fatalf("expected confidence %v, got %#v", confidence, response.CPEConfidence)
	}
	if response.CPEReviewNotes == nil || *response.CPEReviewNotes != reviewNotes {
		t.Fatalf("expected review notes %q, got %#v", reviewNotes, response.CPEReviewNotes)
	}
	if response.CPECandidateCount != 4 {
		t.Fatalf("expected candidate count 4, got %d", response.CPECandidateCount)
	}
	if response.CPEMatchedAt == nil || !response.CPEMatchedAt.Equal(matchedAt) {
		t.Fatalf("expected matched at %v, got %#v", matchedAt, response.CPEMatchedAt)
	}
}
