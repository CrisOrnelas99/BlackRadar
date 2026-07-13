package jwtmiddleware

type JWTMiddlewareError struct {
	Message string
}

func (e JWTMiddlewareError) Error() string {
	return e.Message
}

var (
	ErrUnauthorized             = &JWTMiddlewareError{Message: "Unauthorized"}
	ErrDatabaseUnavailable      = &JWTMiddlewareError{Message: "database unavailable"}
	ErrInternalServer           = &JWTMiddlewareError{Message: "internal server error"}
	ErrJWTManagerRequired       = &JWTMiddlewareError{Message: "JWT authentication manager is required"}
	ErrJWTUserLookupRequired    = &JWTMiddlewareError{Message: "JWT authentication user lookup is required"}
	ErrJWTSessionLookupRequired = &JWTMiddlewareError{Message: "JWT authentication session lookup is required"}
)
