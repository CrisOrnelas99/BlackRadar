// Package model defines the persistence and domain structs used by GORM.
package model

import "time"

// Role names used by the application authorization model.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// User represents an application account stored in PostgreSQL.
type User struct {
	Model
	OrganizationID string `gorm:"type:uuid;column:organization_id;index" json:"-"`
	Username       string `gorm:"not null;uniqueIndex:idx_users_username_active,where:deleted_at IS NULL" json:"username"`
	Email          string `gorm:"not null;uniqueIndex:idx_users_email_active,where:deleted_at IS NULL" json:"email"`
	Role           string `gorm:"not null;default:user" json:"role"`
	PasswordHash   string `gorm:"column:password_hash;not null" json:"-"`
}

// TableName returns the PostgreSQL table name for User.
func (User) TableName() string {
	return "users"
}

// RefreshSession represents a server-side refresh token session for a user.
type RefreshSession struct {
	TokenID    string     `gorm:"column:token_id;primaryKey" json:"-"`
	UserID     string     `gorm:"type:uuid;column:user_id;index;not null" json:"-"`
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
