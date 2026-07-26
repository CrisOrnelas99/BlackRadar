// Package service errors defines asset-risk service failure categories.
package service

// NotFoundError identifies a missing asset-risk resource.
type NotFoundError struct {
	Message string
}

// Error returns the not-found error message.
func (e NotFoundError) Error() string {
	return e.Message
}

// DependencyError identifies a failed asset-risk repository dependency.
type DependencyError struct {
	Message string
}

// Error returns the dependency error message.
func (e DependencyError) Error() string {
	return e.Message
}

// InternalError identifies an unexpected asset-risk service failure.
type InternalError struct {
	Message string
}

// Error returns the internal error message.
func (e InternalError) Error() string {
	return e.Message
}

var (
	ErrAssetRiskNotFound   = &NotFoundError{Message: "asset risk asset not found"}
	ErrAssetRiskDependency = &DependencyError{Message: "asset risk dependency unavailable"}
	ErrAssetRiskInternal   = &InternalError{Message: "asset risk service error"}
)
