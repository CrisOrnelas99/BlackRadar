// Package audit provides durable audit-event persistence.
package audit

import (
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

// RepositoryInterface defines the audit-event persistence contract.
type RepositoryInterface interface {
	/*
		Create persists one append-only audit event using the request-scoped
		database when present. Implementations must not mutate or delete existing
		events and must return repository sentinel errors for invalid input or
		persistence failures.
	*/
	Create(ec *appcontext.GinContext, event model.AuditEvent) error
}
