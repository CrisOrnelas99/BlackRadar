package middleware

type MiddlewareError struct {
	Message string
}

func (e MiddlewareError) Error() string {
	return e.Message
}

var (
	ErrSuspiciousRequest         = &MiddlewareError{Message: "Request blocked"}
	ErrForbidden                 = &MiddlewareError{Message: "forbidden"}
	ErrUnauthorized              = &MiddlewareError{Message: "Unauthorized"}
	ErrDatabaseUnavailable       = &MiddlewareError{Message: "database unavailable"}
	ErrDatabaseTransactionFailed = &MiddlewareError{Message: "database transaction failed"}
	ErrRateLimited               = &MiddlewareError{Message: "Rate limit exceeded."}
)
