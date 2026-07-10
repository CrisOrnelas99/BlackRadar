// Package model defines shared persistence model fields.
package model

import (
	"time"

	"gorm.io/gorm"
)

// Model contains the shared UUID identity, timestamp, soft-delete, and audit metadata.
type Model struct {
	ID          string         `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	CreatedAt   time.Time      `gorm:"column:created_at" json:"createdAt"`
	UpdatedAt   time.Time      `gorm:"column:updated_at" json:"updatedAt"`
	DeletedAt   gorm.DeletedAt `gorm:"column:deleted_at;index" json:"-"`
	UpdatedByID *string        `gorm:"type:uuid;column:updated_by_id;index" json:"-"`
}
