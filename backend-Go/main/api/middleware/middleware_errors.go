package middleware

type MiddlewareError struct {
	Message string
}

func (e MiddlewareError) Error() string {
	return e.Message
}

var (
	ErrSuspiciousRequest = &MiddlewareError{Message: "Request blocked"}
)

