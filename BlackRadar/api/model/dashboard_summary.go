// Package model defines the dashboard summary persistence model.
package model

import "time"

// DashboardSummary stores the latest validated AI summary for an organization.
type DashboardSummary struct {
	Model
	OrganizationID    string    `gorm:"type:uuid;column:organization_id;not null;uniqueIndex:idx_dashboard_summaries_organization" json:"-"`
	SummaryPayload    string    `gorm:"type:jsonb;column:summary_payload;not null" json:"-"`
	GeneratedAt       time.Time `gorm:"column:generated_at;not null" json:"generatedAt"`
	GeneratedByUserID string    `gorm:"type:uuid;column:generated_by_user_id;not null" json:"-"`
}

// TableName returns the PostgreSQL table name for DashboardSummary.
func (DashboardSummary) TableName() string {
	return "dashboard_summaries"
}
