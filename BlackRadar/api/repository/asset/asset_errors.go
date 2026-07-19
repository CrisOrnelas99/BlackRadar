package repository

type AssetRepositoryError struct {
	Message string
}

func (e AssetRepositoryError) Error() string {
	return e.Message
}

var (
	ErrAssetNotFound         = &AssetRepositoryError{Message: "asset not found"}
	ErrVulnerabilityNotFound = &AssetRepositoryError{Message: "vulnerability not found"}
	ErrDuplicateAssignment   = &AssetRepositoryError{Message: "duplicate asset vulnerability assignment"}
	ErrPrimaryKeyConflict    = &AssetRepositoryError{Message: "primary key conflict"}
	ErrInvalidReference      = &AssetRepositoryError{Message: "invalid reference"}
	ErrInvalidData           = &AssetRepositoryError{Message: "invalid data"}
	ErrPersistenceFailure    = &AssetRepositoryError{Message: "persistence failure"}
)
