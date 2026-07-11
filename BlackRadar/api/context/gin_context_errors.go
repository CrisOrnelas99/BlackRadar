package requestcontext

type RequestContextError struct {
	Message string
}

func (e RequestContextError) Error() string {
	return e.Message
}

var (
	ErrContextNotInitialized = &RequestContextError{Message: "request context has not been initialized"}
	ErrPrincipalNotSet       = &RequestContextError{Message: "authenticated principal has not been set"}
	ErrInvalidPrincipal      = &RequestContextError{Message: "authenticated principal is invalid"}
	ErrUsernameNotSet        = &RequestContextError{Message: "authenticated principal username has not been set"}
	ErrRoleNotSet            = &RequestContextError{Message: "authenticated principal role has not been set"}
)
