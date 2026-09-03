// Package model defines the persistence and domain structs used by GORM.
package model

import (
	"time"

	"blackradar/api/common/pagination"
)

// Role names used by the application authorization model.
const (
	RoleAdmin  = "admin"
	RoleMaster = "master"
	RoleUser   = "user"

	SystemAdminID = "77000000-0000-4000-8000-000000000001"

	AccountStatusActive      = "active"
	AccountStatusDeactivated = "deactivated"
)

// UserListQuery contains the bounded pagination requested for administrator account review.
type UserListQuery struct {
	Pagination pagination.Request
}

// User represents an application account stored in PostgreSQL.
type User struct {
	Model
	OrganizationID    string     `gorm:"type:uuid;column:organization_id;index" json:"-"`
	FullName          string     `gorm:"column:full_name;not null;default:''" json:"fullName"`
	Username          string     `gorm:"not null;uniqueIndex:idx_users_username_active,where:deleted_at IS NULL" json:"username"`
	Email             string     `gorm:"not null;uniqueIndex:idx_users_email_active,where:deleted_at IS NULL" json:"email"`
	Role              string     `gorm:"not null;default:user" json:"role"`
	AccountStatus     string     `gorm:"column:account_status;not null;default:active" json:"accountStatus"`
	PasswordHash      string     `gorm:"column:password_hash;not null" json:"-"`
	FailedLoginCount  int        `gorm:"column:failed_login_count;not null;default:0" json:"-"`
	LastFailedLoginAt *time.Time `gorm:"column:last_failed_login_at" json:"-"`
	LockedUntil       *time.Time `gorm:"column:locked_until" json:"-"`
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
