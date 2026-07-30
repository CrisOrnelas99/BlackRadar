package model

import "time"

// ProviderUsageBucket stores durable request usage for one provider window.
type ProviderUsageBucket struct {
	ID           string    `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"-"`
	Provider     string    `gorm:"size:32;uniqueIndex:idx_provider_usage_window,priority:1;not null" json:"-"`
	WindowStart  time.Time `gorm:"uniqueIndex:idx_provider_usage_window,priority:2;not null" json:"-"`
	RequestCount int       `gorm:"not null" json:"-"`
	CreatedAt    time.Time `json:"-"`
	UpdatedAt    time.Time `json:"-"`
}
