// Package model defines the domain and persistence structs used by GORM.
package model

import "time"

// SingleOrganizationID is the stable organization used until organization
// membership and switching are introduced.
const SingleOrganizationID = "77000000-0000-4000-8000-000000000010"

// Organization represents the current tenant boundary.
type Organization struct {
	ID        string    `gorm:"type:uuid;primaryKey" json:"-"`
	Name      string    `gorm:"not null" json:"name"`
	Slug      string    `gorm:"not null;uniqueIndex" json:"slug"`
	CreatedAt time.Time `gorm:"column:created_at" json:"createdAt"`
	UpdatedAt time.Time `gorm:"column:updated_at" json:"updatedAt"`
}

// TableName returns the PostgreSQL table name for Organization.
func (Organization) TableName() string { return "organizations" }
