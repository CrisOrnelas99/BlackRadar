package repository

type OrganizationRepositoryError struct {
	Message string
}

func (e OrganizationRepositoryError) Error() string {
	return e.Message
}

var (
	ErrDuplicateData      = &OrganizationRepositoryError{Message: "duplicate data"}
	ErrPrimaryKeyConflict = &OrganizationRepositoryError{Message: "primary key conflict"}
	ErrInvalidData        = &OrganizationRepositoryError{Message: "invalid data"}
	ErrPersistenceFailure = &OrganizationRepositoryError{Message: "persistence failure"}
)
