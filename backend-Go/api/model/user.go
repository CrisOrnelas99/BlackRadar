// Package model defines the persistence and domain structs used by GORM.
package model

// Role names used by the application authorization model.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// User represents an application account stored in PostgreSQL.
type User struct {
	ID             int64  `gorm:"primaryKey" json:"id"`
	OrganizationID int64  `gorm:"column:organization_id;index" json:"-"`
	Username       string `gorm:"not null" json:"username"`
	Email          string `gorm:"not null" json:"email"`
	Role           string `gorm:"not null;default:user" json:"role"`
	PasswordHash   string `gorm:"column:password_hash;not null" json:"-"`
}

// TableName returns the PostgreSQL table name for User.
func (User) TableName() string {
	return "users"
}
