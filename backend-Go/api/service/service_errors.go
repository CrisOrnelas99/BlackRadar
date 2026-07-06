package service

type ServiceError struct {
	Message string
}

func (e ServiceError) Error() string {
	return e.Message
}

var (
	ErrInvalidRequestData = &ServiceError{Message: "invalid request data"}
	ErrConflict           = &ServiceError{Message: "conflict"}
	ErrNotFound           = &ServiceError{Message: "not found"}
	ErrInvalidCredentials = &ServiceError{Message: "invalid credentials"}
	ErrForbidden          = &ServiceError{Message: "forbidden"}
	ErrRateLimited        = &ServiceError{Message: "rate limited"}
	ErrExternalService    = &ServiceError{Message: "external service unavailable"}
	ErrInternal           = &ServiceError{Message: "internal service error"}
)
