// Package asset_match errors defines asset match service error categories.
package asset_match

// ValidationError identifies invalid asset match input.
type ValidationError struct {
	Message string
}

// Error returns the validation error message.
func (e ValidationError) Error() string {
	return e.Message
}

// NotFoundError identifies missing asset match resources.
type NotFoundError struct {
	Message string
}

// Error returns the not-found error message.
func (e NotFoundError) Error() string {
	return e.Message
}

// DependencyError identifies failed repository or external dependencies.
type DependencyError struct {
	Message string
}

// Error returns the dependency error message.
func (e DependencyError) Error() string {
	return e.Message
}

// InternalError identifies unexpected asset match service failures.
type InternalError struct {
	Message string
}

// Error returns the internal error message.
func (e InternalError) Error() string {
	return e.Message
}

var (
	ErrInvalidCVEID         = &ValidationError{Message: "invalid CVE ID"}
	ErrCVENotFound          = &NotFoundError{Message: "CVE not found"}
	ErrNVDLookupRateLimited = &DependencyError{Message: "NVD lookup rate limited"}
	ErrMatchDependency      = &DependencyError{Message: "match dependency unavailable"}
	ErrMatchExternalService = &DependencyError{Message: "external service unavailable"}
	ErrMatchInternal        = &InternalError{Message: "match service error"}
)
