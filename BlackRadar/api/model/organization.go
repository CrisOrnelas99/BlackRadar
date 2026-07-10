// Package model defines the persistence and domain structs used by GORM.
package model

// Organization represents a tenant boundary stored in PostgreSQL.
type Organization struct {
	Model
	Name string `gorm:"not null;uniqueIndex:idx_organizations_name_active,where:deleted_at IS NULL" json:"name"`
}

// TableName returns the PostgreSQL table name for Organization.
func (Organization) TableName() string {
	return "organizations"
}
