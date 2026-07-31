// Package audit provides security audit-event application services.
package audit

import appcontext "blackradar/api/platform/requestcontext"

// Service defines the audit event boundary consumed by write workflows.
type Service interface {
	/*
		Record persists one security event using trusted server-side context.
		Implementations must reject unsafe or incomplete events and must never
		persist credentials, tokens, raw request bodies, or raw AI input.
	*/
	Record(ec *appcontext.GinContext, input EventInput) error
}
