package model

import "time"

type Asset struct {
	ID              int64           `gorm:"primaryKey" json:"id"`
	UserID          int64           `gorm:"column:user_id" json:"-"`
	Name            string          `gorm:"not null" json:"name"`
	Type            string          `gorm:"not null" json:"type"`
	IPAddress       string          `gorm:"column:ip_address;not null" json:"ipAddress"`
	OperatingSystem *string         `gorm:"column:operating_system" json:"operatingSystem"`
	Owner           string          `gorm:"not null" json:"owner"`
	Criticality     string          `gorm:"not null" json:"criticality"`
	RiskScore       int16           `gorm:"column:risk_score;not null;default:0" json:"riskScore"`
	RiskLevel       string          `gorm:"column:risk_level;not null;default:Low" json:"riskLevel"`
	Vulnerabilities []Vulnerability `gorm:"many2many:asset_vulnerabilities;" json:"vulnerabilities,omitempty"`
	CreatedAt       time.Time       `gorm:"column:created_at" json:"createdAt"`
	UpdatedAt       time.Time       `gorm:"column:updated_at" json:"updatedAt"`
}

func (Asset) TableName() string {
	return "assets"
}
