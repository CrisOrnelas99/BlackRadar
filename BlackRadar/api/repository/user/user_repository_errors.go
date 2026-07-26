// Package repository errors defines user persistence sentinel errors.
package repository

// UserRepositoryError identifies a user repository failure category.
type UserRepositoryError struct {
	Message string
}

// Error returns the user repository error message.
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
