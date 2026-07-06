// Package model defines the persistence and domain structs used by GORM.
package model

// Asset represents a tenant-scoped asset stored in PostgreSQL.
type Asset struct {
	Model
	OrganizationID    string           `gorm:"type:uuid;column:organization_id;index" json:"-"`
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
