package shared

type DBError struct {
	Message string
}

func (e DBError) Error() string {
	return e.Message
}

var (
	ErrForeignKeyViolation      = &DBError{Message: "foreign key violation"}
	ErrCheckConstraintViolation = &DBError{Message: "check constraint violation"}
	ErrUniqueViolation          = &DBError{Message: "unique violation"}
)

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
