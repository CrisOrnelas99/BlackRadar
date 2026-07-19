package service

type AuthInvalidRequestError struct {
	Message string
}

func (e AuthInvalidRequestError) Error() string {
	return e.Message
}

var (
	ErrInvalidRegisterRequest = &AuthInvalidRequestError{Message: "invalid registration request"}
)

type AuthConflictError struct {
	Message string
}

func (e AuthConflictError) Error() string {
	return e.Message
}

var (
	ErrUsernameAlreadyExists = &AuthConflictError{Message: "username already exists"}
	ErrEmailAlreadyExists    = &AuthConflictError{Message: "email already exists"}
)

type AuthCredentialsError struct {
	Message string
}

func (e AuthCredentialsError) Error() string {
	return e.Message
}

var (
	ErrInvalidLoginCredentials = &AuthCredentialsError{Message: "invalid credentials"}
	ErrInvalidRefreshToken     = &AuthCredentialsError{Message: "invalid refresh token"}
)
