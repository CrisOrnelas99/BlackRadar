package gormmiddleware

type GormMiddlewareError struct {
	Message string
}

func (e GormMiddlewareError) Error() string {
	return e.Message
}

var ErrDatabaseUnavailable = &GormMiddlewareError{Message: "database unavailable"}
