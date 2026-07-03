// Package model defines the persistence and domain structs used by GORM.
package model

import "time"

// AssetCPEReviewStatus values describe how a product match was handled.
const (
	AssetCPEReviewStatusAccepted    = "accepted"
	AssetCPEReviewStatusNeedsReview = "needs_review"
	AssetCPEReviewStatusRejected    = "rejected"
)

// AssetAssessment stores mutable risk and CPE match state separately from the core asset record.
type AssetAssessment struct {
	ID                 int64      `gorm:"primaryKey;autoIncrement:false" json:"id"`
	RiskScore          int16      `gorm:"column:risk_score;not null;default:0" json:"riskScore"`
	ProductFingerprint *string    `gorm:"column:product_fingerprint;type:text" json:"productFingerprint,omitempty"`
	SelectedCPE        *string    `gorm:"column:selected_cpe;type:text" json:"selectedCpe,omitempty"`
	CPEConfidence      *float64   `gorm:"column:cpe_confidence" json:"cpeConfidence,omitempty"`
	CPEReviewStatus    string     `gorm:"column:cpe_review_status;not null;default:needs_review" json:"cpeReviewStatus"`
	CPEReviewNotes     *string    `gorm:"column:cpe_review_notes;type:text" json:"cpeReviewNotes,omitempty"`
	CPECandidateCount  int        `gorm:"column:cpe_candidate_count;not null;default:0" json:"cpeCandidateCount"`
	CPEMatchedAt       *time.Time `gorm:"column:cpe_matched_at" json:"cpeMatchedAt,omitempty"`
	CreatedAt          time.Time  `gorm:"column:created_at" json:"createdAt"`
	UpdatedAt          time.Time  `gorm:"column:updated_at" json:"updatedAt"`
}

// TableName returns the PostgreSQL table name for AssetAssessment.
func (AssetAssessment) TableName() string {
	return "asset_assessments"
}
