package service

type ValidationError struct {
	Message string
}

func (e ValidationError) Error() string {
	return e.Message
}

type ConflictError struct {
	Message string
}

func (e ConflictError) Error() string {
	return e.Message
}

type UnauthorizedError struct {
	Message string
}

func (e UnauthorizedError) Error() string {
	return e.Message
}

type DependencyError struct {
	Message string
}

func (e DependencyError) Error() string {
	return e.Message
}

type InternalError struct {
	Message string
}

func (e InternalError) Error() string {
	return e.Message
}

var (
	ErrInvalidRegisterRequest  = &ValidationError{Message: "invalid registration request"}
	ErrUsernameAlreadyExists   = &ConflictError{Message: "username already exists"}
	ErrEmailAlreadyExists      = &ConflictError{Message: "email already exists"}
	ErrInvalidLoginCredentials = &UnauthorizedError{Message: "invalid credentials"}
	ErrInvalidRefreshToken     = &UnauthorizedError{Message: "invalid refresh token"}
	ErrUserDependency          = &DependencyError{Message: "user dependency unavailable"}
	ErrUserInternal            = &InternalError{Message: "user service error"}
)
