// Package service errors defines user service error categories.
package service

// ValidationError identifies invalid user input.
type ValidationError struct {
	Message string
}

// Error returns the validation error message.
func (e ValidationError) Error() string {
	return e.Message
}

// ConflictError identifies user state conflicts.
type ConflictError struct {
	Message string
}

// Error returns the conflict error message.
func (e ConflictError) Error() string {
	return e.Message
}

// UnauthorizedError identifies invalid authentication credentials or sessions.
type UnauthorizedError struct {
	Message string
}

// Error returns the unauthorized error message.
func (e UnauthorizedError) Error() string {
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

// InternalError identifies unexpected user service failures.
type InternalError struct {
	Message string
}

// Error returns the internal error message.
func (e InternalError) Error() string {
	return e.Message
}

var (
	ErrInvalidCreateUserRequest = &ValidationError{Message: "invalid user provisioning request"}
	ErrUsernameAlreadyExists    = &ConflictError{Message: "username already exists"}
	ErrEmailAlreadyExists       = &ConflictError{Message: "email already exists"}
	ErrInvalidLoginCredentials  = &UnauthorizedError{Message: "invalid credentials"}
	ErrLoginBackoff             = &UnauthorizedError{Message: "too many login attempts"}
	ErrInvalidRefreshToken      = &UnauthorizedError{Message: "invalid refresh token"}
	ErrUserDependency           = &DependencyError{Message: "user dependency unavailable"}
	ErrUserInternal             = &InternalError{Message: "user service error"}
)
