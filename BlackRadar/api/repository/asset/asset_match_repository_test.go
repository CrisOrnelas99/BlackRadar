package repository

import (
	"testing"
	"time"
)

func TestAssetMatchUpdateCarriesMatchState(t *testing.T) {
	now := time.Unix(123, 0)
	productFingerprint := "vendor=acme"
	selectedCPE := "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"
	confidence := 0.92
	reviewNotes := "match requires review"

	update := AssetMatchUpdate{
		ProductFingerprint: &productFingerprint,
		SelectedCPE:        &selectedCPE,
		CPEConfidence:      &confidence,
		CPEReviewStatus:    "accepted",
		CPEReviewNotes:     &reviewNotes,
		CPECandidateCount:  3,
		CPEMatchedAt:       &now,
	}

	if update.CPEReviewStatus != "accepted" {
		t.Fatalf("expected accepted review status, got %q", update.CPEReviewStatus)
	}
	if update.CPECandidateCount != 3 {
		t.Fatalf("expected candidate count 3, got %d", update.CPECandidateCount)
	}
	if update.CPEMatchedAt == nil || !update.CPEMatchedAt.Equal(now) {
		t.Fatalf("expected matched-at timestamp to be preserved, got %#v", update.CPEMatchedAt)
	}
}
