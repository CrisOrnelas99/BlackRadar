package service

type ValidationError struct {
	Message string
}

func (e ValidationError) Error() string {
	return e.Message
}

type NotFoundError struct {
	Message string
}

func (e NotFoundError) Error() string {
	return e.Message
}

type UnauthorizedError struct {
	Message string
}

func (e UnauthorizedError) Error() string {
	return e.Message
}

type ForbiddenError struct {
	Message string
}

func (e ForbiddenError) Error() string {
	return e.Message
}

type RemoteServiceError struct {
	Message string
}

func (e RemoteServiceError) Error() string {
	return e.Message
}

var (
	ErrInvalidRequestData  = &ValidationError{Message: "invalid request data"}
	ErrConflict            = &ValidationError{Message: "conflict"}
	ErrNotFound            = &NotFoundError{Message: "not found"}
	ErrInvalidCredentials  = &UnauthorizedError{Message: "invalid credentials"}
	ErrForbidden           = &ForbiddenError{Message: "forbidden"}
	ErrRemoteService       = &RemoteServiceError{Message: "remote service error"}
	ErrRemoteRejected      = &ValidationError{Message: "remote service rejected request"}
	ErrInvalidRemoteResult = &RemoteServiceError{Message: "invalid remote service response"}
)
