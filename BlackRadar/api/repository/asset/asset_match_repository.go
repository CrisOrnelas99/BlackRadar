// Package repository defines persistence contracts used by the service layer.
package repository

import "time"

// AssetMatchUpdate carries the backend-generated CPE match state for an asset.
type AssetMatchUpdate struct {
	ProductFingerprint *string
	SelectedCPE        *string
	CPEConfidence      *float64
	CPEReviewStatus    string
	CPEReviewNotes     *string
	CPECandidateCount  int
	CPEMatchedAt       *time.Time
}
