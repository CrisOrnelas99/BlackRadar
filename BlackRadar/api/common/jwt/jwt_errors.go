package jwt

type JWTError struct {
	Message string
}

func (e JWTError) Error() string {
	return e.Message
}

var (
	ErrUnexpectedSigningMethod = &JWTError{Message: "unexpected signing method"}
	ErrInvalidToken            = &JWTError{Message: "invalid token"}
	ErrMissingSubject          = &JWTError{Message: "missing subject"}
	ErrInvalidScope            = &JWTError{Message: "invalid scope"}
	ErrInvalidTokenUse         = &JWTError{Message: "invalid token use"}
	ErrMissingSecret           = &JWTError{Message: "missing jwt secret"}
)
