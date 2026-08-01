// Package repository errors defines asset-risk persistence failure categories.
package repository

// AssetRiskRepositoryError identifies an asset-risk repository failure category.
type AssetRiskRepositoryError struct {
	Message string
}

// Error returns the asset-risk repository error message.
func (e AssetRiskRepositoryError) Error() string {
	return e.Message
}

var (
	ErrRecordNotFound     = &AssetRiskRepositoryError{Message: "record not found"}
	ErrPersistenceFailure = &AssetRiskRepositoryError{Message: "persistence failure"}
)
