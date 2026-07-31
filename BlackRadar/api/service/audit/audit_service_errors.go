// Package audit provides security audit-event application services.
package audit

// ServiceError identifies an audit-event service failure category.
type ServiceError struct {
	Message string
}

// Error returns the audit service error message.
func (e ServiceError) Error() string {
	return e.Message
}

var (
	ErrInvalidEvent = &ServiceError{Message: "invalid audit event"}
	ErrUnavailable  = &ServiceError{Message: "audit service unavailable"}
)
