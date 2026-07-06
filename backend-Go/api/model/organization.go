// Package model defines the persistence and domain structs used by GORM.
package model

import (
	"time"

	"gorm.io/gorm"
)

// Organization represents a tenant boundary stored in PostgreSQL.
type Organization struct {
	ID        int64          `gorm:"primaryKey" json:"id"`
	Name      string         `gorm:"not null;uniqueIndex:idx_organizations_name_active,where:deleted_at IS NULL" json:"name"`
	CreatedAt time.Time      `gorm:"column:created_at" json:"createdAt"`
	UpdatedAt time.Time      `gorm:"column:updated_at" json:"updatedAt"`
	DeletedAt gorm.DeletedAt `gorm:"column:deleted_at;index" json:"-"`
}

// TableName returns the PostgreSQL table name for Organization.
func (Organization) TableName() string {
	return "organizations"
}
