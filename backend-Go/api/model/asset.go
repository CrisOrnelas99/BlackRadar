// Package model defines the persistence and domain structs used by GORM.
package model

import "time"

// Asset represents a tenant-scoped asset stored in PostgreSQL.
type Asset struct {
	ID                 int64           `gorm:"primaryKey" json:"id"`
	OrganizationID     int64           `gorm:"column:organization_id;index" json:"-"`
	UserID             int64           `gorm:"column:user_id;index" json:"-"`
	Name               string          `gorm:"not null" json:"name"`
	Type               string          `gorm:"not null" json:"type"`
	OperatingSystem    *string         `gorm:"column:operating_system" json:"operatingSystem"`
	Vendor             *string         `gorm:"column:vendor" json:"vendor,omitempty"`
	Product            *string         `gorm:"column:product" json:"product,omitempty"`
	Version            *string         `gorm:"column:version" json:"version,omitempty"`
	DeviceModel        *string         `gorm:"column:device_model" json:"deviceModel,omitempty"`
	Owner              string          `gorm:"not null" json:"owner"`
	Criticality        string          `gorm:"not null" json:"criticality"`
	RiskScore          int16           `gorm:"column:risk_score;not null;default:0" json:"riskScore"`
	RiskLevel          string          `gorm:"column:risk_level;not null;default:Low" json:"riskLevel"`
	ProductFingerprint *string         `gorm:"column:product_fingerprint;type:text" json:"productFingerprint,omitempty"`
	SelectedCPE        *string         `gorm:"column:selected_cpe;type:text" json:"selectedCpe,omitempty"`
	CPEConfidence      *float64        `gorm:"column:cpe_confidence" json:"cpeConfidence,omitempty"`
	CPEReviewStatus    string          `gorm:"column:cpe_review_status;not null;default:needs_review" json:"cpeReviewStatus"`
	CPEReviewNotes     *string         `gorm:"column:cpe_review_notes;type:text" json:"cpeReviewNotes,omitempty"`
	CPECandidateCount  int             `gorm:"column:cpe_candidate_count;not null;default:0" json:"cpeCandidateCount"`
	CPEMatchedAt       *time.Time      `gorm:"column:cpe_matched_at" json:"cpeMatchedAt,omitempty"`
	Vulnerabilities    []Vulnerability `gorm:"many2many:asset_vulnerabilities;" json:"vulnerabilities,omitempty"`
	CreatedAt          time.Time       `gorm:"column:created_at" json:"createdAt"`
	UpdatedAt          time.Time       `gorm:"column:updated_at" json:"updatedAt"`
}

// TableName returns the PostgreSQL table name for Asset.
func (Asset) TableName() string {
	return "assets"
}
