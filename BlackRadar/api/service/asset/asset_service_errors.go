// Package service errors defines asset service error categories.
package service

// ValidationError identifies invalid asset input.
type ValidationError struct {
	Message string
}

// Error returns the validation error message.
func (e ValidationError) Error() string {
	return e.Message
}

// ConflictError identifies asset state conflicts.
type ConflictError struct {
	Message string
}

// Error returns the conflict error message.
func (e ConflictError) Error() string {
	return e.Message
}

// ForbiddenError identifies denied asset operations.
type ForbiddenError struct {
	Message string
}

// Error returns the forbidden error message.
func (e ForbiddenError) Error() string {
	return e.Message
}

// NotFoundError identifies missing asset resources.
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

// InternalError identifies unexpected asset service failures.
type InternalError struct {
	Message string
}

// Error returns the internal error message.
func (e InternalError) Error() string {
	return e.Message
}

var (
	ErrInvalidAssetData      = &ValidationError{Message: "invalid asset data"}
	ErrInvalidAssetText      = &ValidationError{Message: "invalid asset text"}
	ErrDuplicateAsset        = &ConflictError{Message: "asset already exists"}
	ErrAssetPermissionDenied = &ForbiddenError{Message: "asset permission denied"}
	ErrAssetNotFound         = &NotFoundError{Message: "asset not found"}
	ErrAssetDependency       = &DependencyError{Message: "asset dependency unavailable"}
	ErrAssetExternalService  = &DependencyError{Message: "external service unavailable"}
	ErrAssetInternal         = &InternalError{Message: "asset service error"}
)
