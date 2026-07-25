package repository

type UserRepositoryError struct {
	Message string
}

func (e UserRepositoryError) Error() string {
	return e.Message
}

var (
	ErrRecordNotFound           = &UserRepositoryError{Message: "record not found"}
	ErrUniqueViolation          = &UserRepositoryError{Message: "unique violation"}
	ErrPrimaryKeyViolation      = &UserRepositoryError{Message: "primary key violation"}
	ErrForeignKeyViolation      = &UserRepositoryError{Message: "foreign key violation"}
	ErrNotNullViolation         = &UserRepositoryError{Message: "not null violation"}
	ErrCheckConstraintViolation = &UserRepositoryError{Message: "check constraint violation"}
	ErrPermissionDenied         = &UserRepositoryError{Message: "permission denied"}
	ErrPersistenceFailure       = &UserRepositoryError{Message: "persistence failure"}
)
