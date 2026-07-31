// Package audit provides durable audit-event persistence.
package audit

import (
	"fmt"

	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"

	"gorm.io/gorm"
)

// Repository persists append-only security audit events.
type Repository struct {
	db *gorm.DB
}

// NewRepository creates an audit repository backed by the supplied database.
func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// Create persists one append-only audit event.
func (r *Repository) Create(ec *appcontext.GinContext, event model.AuditEvent) error {
	if event.RequestID == "" || event.Action == "" || event.ResourceType == "" || event.Result == "" {
		return ErrInvalidAuditEvent
	}
	database := r.db
	if ec != nil && ec.Database() != nil {
		database = ec.Database()
	}
	if database == nil || ec == nil {
		return ErrDatabaseRequired
	}
	if err := database.WithContext(ec.RequestContext()).Create(&event).Error; err != nil {
		return fmt.Errorf("%w: create audit event: %w", ErrPersistenceFailure, err)
	}
	return nil
}

var _ RepositoryInterface = (*Repository)(nil)
