package db

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
