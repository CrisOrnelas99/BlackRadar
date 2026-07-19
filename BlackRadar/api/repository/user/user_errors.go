package repository

type UserRepositoryError struct {
	Message string
}

func (e UserRepositoryError) Error() string {
	return e.Message
}

var (
	ErrRefreshSessionNotFound = &UserRepositoryError{Message: "refresh session not found"}
	ErrDuplicateData          = &UserRepositoryError{Message: "duplicate data"}
	ErrPrimaryKeyConflict     = &UserRepositoryError{Message: "primary key conflict"}
	ErrInvalidReference       = &UserRepositoryError{Message: "invalid reference"}
	ErrInvalidData            = &UserRepositoryError{Message: "invalid data"}
	ErrPersistenceFailure     = &UserRepositoryError{Message: "persistence failure"}
)
