// Package model defines the persistence and domain structs used by GORM.
package model

import "time"

// RefreshSession represents a server-side refresh token session for a user.
type RefreshSession struct {
	TokenID    string     `gorm:"column:token_id;primaryKey" json:"-"`
	UserID     int64      `gorm:"column:user_id;index;not null" json:"-"`
	DeviceName string     `gorm:"column:device_name;not null" json:"deviceName"`
	RevokedAt  *time.Time `gorm:"column:revoked_at" json:"-"`
	ExpiresAt  time.Time  `gorm:"column:expires_at;not null" json:"expiresAt"`
	CreatedAt  time.Time  `gorm:"column:created_at" json:"createdAt"`
	UpdatedAt  time.Time  `gorm:"column:updated_at" json:"updatedAt"`
}

// TableName returns the PostgreSQL table name for RefreshSession.
func (RefreshSession) TableName() string {
	return "refresh_sessions"
}
