// Package repository errors defines asset persistence sentinel errors.
package repository

// AssetRepositoryError identifies an asset repository failure category.
type AssetRepositoryError struct {
	Message string
}

// Error returns the asset repository error message.
func (e AssetRepositoryError) Error() string {
	return e.Message
}

var (
	ErrRecordNotFound           = &AssetRepositoryError{Message: "record not found"}
	ErrPrimaryKeyViolation      = &AssetRepositoryError{Message: "primary key violation"}
	ErrForeignKeyViolation      = &AssetRepositoryError{Message: "foreign key violation"}
	ErrNotNullViolation         = &AssetRepositoryError{Message: "not null violation"}
	ErrCheckConstraintViolation = &AssetRepositoryError{Message: "check constraint violation"}
	ErrPersistenceFailure       = &AssetRepositoryError{Message: "persistence failure"}
)
