package security

type SecurityError struct {
	Message string
}

func (e SecurityError) Error() string {
	return e.Message
}

var (
	ErrUnexpectedSigningMethod = &SecurityError{Message: "unexpected signing method"}
	ErrInvalidToken            = &SecurityError{Message: "invalid token"}
	ErrMissingSubject          = &SecurityError{Message: "missing subject"}
	ErrInvalidScope            = &SecurityError{Message: "invalid scope"}
	ErrInvalidTokenUse         = &SecurityError{Message: "invalid token use"}
	ErrMissingSecret           = &SecurityError{Message: "missing jwt secret"}
)
