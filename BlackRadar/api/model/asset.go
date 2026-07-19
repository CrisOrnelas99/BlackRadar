// Package model defines the persistence and domain structs used by GORM.
package model

import (
	"time"

	"gorm.io/gorm"
)

// AssetCPEReviewStatus values describe how a product match was handled.
const (
	AssetCPEReviewStatusAccepted    = "accepted"
	AssetCPEReviewStatusNeedsReview = "needs_review"
	AssetCPEReviewStatusRejected    = "rejected"
)

// Asset represents a user-scoped asset stored in PostgreSQL.
type Asset struct {
	Model
	UserID            string           `gorm:"type:uuid;column:user_id;index" json:"-"`
	AssetAssessmentID *string          `gorm:"type:uuid;column:asset_assessment_id;not null;uniqueIndex" json:"-"`
	Name              string           `gorm:"not null" json:"name"`
	Type              string           `gorm:"not null" json:"type"`
	OperatingSystem   *string          `gorm:"column:operating_system" json:"operatingSystem"`
	Vendor            *string          `gorm:"column:vendor" json:"vendor,omitempty"`
	Product           *string          `gorm:"column:product" json:"product,omitempty"`
	Version           *string          `gorm:"column:version" json:"version,omitempty"`
	DeviceModel       *string          `gorm:"column:device_model" json:"deviceModel,omitempty"`
	Owner             string           `gorm:"not null" json:"owner"`
	Criticality       string           `gorm:"not null" json:"criticality"`
	RiskLevel         *string          `gorm:"column:risk_level" json:"riskLevel"`
	Assessment        *AssetAssessment `gorm:"foreignKey:AssetAssessmentID;references:ID" json:"-"`
	Vulnerabilities   []Vulnerability  `gorm:"many2many:asset_vulnerabilities;" json:"vulnerabilities,omitempty"`
}

// TableName returns the PostgreSQL table name for Asset.
func (Asset) TableName() string {
	return "assets"
}

// AssetAssessment stores mutable risk and CPE match state separately from the core asset record.
type AssetAssessment struct {
	Model
	RiskScore          int16      `gorm:"column:risk_score;not null;default:0" json:"riskScore"`
	ProductFingerprint *string    `gorm:"column:product_fingerprint;type:text" json:"productFingerprint,omitempty"`
	SelectedCPE        *string    `gorm:"column:selected_cpe;type:text" json:"selectedCpe,omitempty"`
	CPEConfidence      *float64   `gorm:"column:cpe_confidence" json:"cpeConfidence,omitempty"`
	CPEReviewStatus    string     `gorm:"column:cpe_review_status;not null;default:needs_review" json:"cpeReviewStatus"`
	CPEReviewNotes     *string    `gorm:"column:cpe_review_notes;type:text" json:"cpeReviewNotes,omitempty"`
	CPECandidateCount  int        `gorm:"column:cpe_candidate_count;not null;default:0" json:"cpeCandidateCount"`
	CPEMatchedAt       *time.Time `gorm:"column:cpe_matched_at" json:"cpeMatchedAt,omitempty"`
}

// TableName returns the PostgreSQL table name for AssetAssessment.
func (AssetAssessment) TableName() string {
	return "asset_assessments"
}

// AssetVulnerability represents the asset-to-vulnerability assignment bridge.
type AssetVulnerability struct {
	AssetID         string         `gorm:"type:uuid;column:asset_id;not null;uniqueIndex:idx_asset_vulnerabilities_active,where:deleted_at IS NULL" json:"-"`
	VulnerabilityID string         `gorm:"type:uuid;column:vulnerability_id;not null;uniqueIndex:idx_asset_vulnerabilities_active,where:deleted_at IS NULL" json:"-"`
	CreatedAt       time.Time      `gorm:"column:created_at" json:"createdAt"`
	DeletedAt       gorm.DeletedAt `gorm:"column:deleted_at;index" json:"-"`
}

// TableName returns the PostgreSQL table name for AssetVulnerability.
func (AssetVulnerability) TableName() string {
	return "asset_vulnerabilities"
}
