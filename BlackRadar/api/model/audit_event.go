// Package model defines the persistence and domain structs used by GORM.
package model

import "time"

// AuditEvent is an append-only security event used for forensic review.
// It intentionally excludes credentials, tokens, request bodies, and raw AI input.
type AuditEvent struct {
	ID           string    `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	OccurredAt   time.Time `gorm:"column:occurred_at;not null;autoCreateTime;index" json:"occurredAt"`
	RequestID    string    `gorm:"column:request_id;not null;index" json:"requestId"`
	ActorUserID  *string   `gorm:"type:uuid;column:actor_user_id;index" json:"-"`
	Action       string    `gorm:"column:action;not null;index" json:"action"`
	ResourceType string    `gorm:"column:resource_type;not null;index" json:"resourceType"`
	ResourceID   *string   `gorm:"column:resource_id;index" json:"-"`
	Result       string    `gorm:"column:result;not null;index" json:"result"`
	Details      string    `gorm:"column:details;not null;default:''" json:"-"`
}

// TableName returns the PostgreSQL table name for AuditEvent.
func (AuditEvent) TableName() string {
	return "audit_events"
}
