// Package model defines the persistence and domain structs used by GORM.
package model

import "time"

// Organization represents a tenant boundary stored in PostgreSQL.
type Organization struct {
	ID        int64     `gorm:"primaryKey" json:"id"`
	Name      string    `gorm:"not null;uniqueIndex" json:"name"`
	CreatedAt time.Time `gorm:"column:created_at" json:"createdAt"`
	UpdatedAt time.Time `gorm:"column:updated_at" json:"updatedAt"`
}

// TableName returns the PostgreSQL table name for Organization.
func (Organization) TableName() string {
	return "organizations"
}
