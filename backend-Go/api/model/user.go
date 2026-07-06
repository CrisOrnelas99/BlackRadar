// Package model defines the persistence and domain structs used by GORM.
package model

import "gorm.io/gorm"

// Role names used by the application authorization model.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// User represents an application account stored in PostgreSQL.
type User struct {
	ID             int64          `gorm:"primaryKey" json:"id"`
	OrganizationID int64          `gorm:"column:organization_id;index" json:"-"`
	Username       string         `gorm:"not null;uniqueIndex:idx_users_username_active,where:deleted_at IS NULL" json:"username"`
	Email          string         `gorm:"not null;uniqueIndex:idx_users_email_active,where:deleted_at IS NULL" json:"email"`
	Role           string         `gorm:"not null;default:user" json:"role"`
	PasswordHash   string         `gorm:"column:password_hash;not null" json:"-"`
	DeletedAt      gorm.DeletedAt `gorm:"column:deleted_at;index" json:"-"`
}

// TableName returns the PostgreSQL table name for User.
func (User) TableName() string {
	return "users"
}
