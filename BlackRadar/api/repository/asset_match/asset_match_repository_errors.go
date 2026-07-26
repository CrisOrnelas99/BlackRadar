// Package repository errors defines asset match persistence sentinel errors.
package repository

// AssetMatchRepositoryError identifies an asset match repository failure category.
type AssetMatchRepositoryError struct {
	Message string
}

// Error returns the asset match repository error message.
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
