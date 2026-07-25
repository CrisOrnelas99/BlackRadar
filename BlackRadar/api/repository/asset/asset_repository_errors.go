package repository

type AssetRepositoryError struct {
	Message string
}

func (e AssetRepositoryError) Error() string {
	return e.Message
}

var (
	ErrRecordNotFound           = &AssetRepositoryError{Message: "record not found"}
	ErrPrimaryKeyViolation      = &AssetRepositoryError{Message: "primary key violation"}
	ErrForeignKeyViolation      = &AssetRepositoryError{Message: "foreign key violation"}
	ErrNotNullViolation         = &AssetRepositoryError{Message: "not null violation"}
	ErrCheckConstraintViolation = &AssetRepositoryError{Message: "check constraint violation"}
	ErrDuplicateRelationship    = &AssetRepositoryError{Message: "duplicate relationship"}
	ErrPersistenceFailure       = &AssetRepositoryError{Message: "persistence failure"}
)
