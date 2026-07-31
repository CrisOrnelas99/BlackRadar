// Package audit provides durable audit-event persistence.
package audit

// RepositoryError identifies an audit-event persistence failure category.
type RepositoryError struct {
	Message string
}

// Error returns the audit repository error message.
func (e RepositoryError) Error() string {
	return e.Message
}

var (
	ErrDatabaseRequired   = &RepositoryError{Message: "database connection required"}
	ErrInvalidAuditEvent  = &RepositoryError{Message: "invalid audit event"}
	ErrPersistenceFailure = &RepositoryError{Message: "audit event persistence failure"}
)
