package repository

type AssetMatchRepositoryError struct {
	Message string
}

func (e AssetMatchRepositoryError) Error() string {
	return e.Message
}

var (
	ErrRecordNotFound           = &AssetMatchRepositoryError{Message: "record not found"}
	ErrForeignKeyViolation      = &AssetMatchRepositoryError{Message: "foreign key violation"}
	ErrNotNullViolation         = &AssetMatchRepositoryError{Message: "not null violation"}
	ErrCheckConstraintViolation = &AssetMatchRepositoryError{Message: "check constraint violation"}
	ErrPersistenceFailure       = &AssetMatchRepositoryError{Message: "persistence failure"}
)
