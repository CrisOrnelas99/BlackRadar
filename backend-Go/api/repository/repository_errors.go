package repository

type RepositoryError struct {
	Message string
}

func (e RepositoryError) Error() string {
	return e.Message
}

var (
	ErrAssetNotFound          = &RepositoryError{Message: "asset not found"}
	ErrVulnerabilityNotFound  = &RepositoryError{Message: "vulnerability not found"}
	ErrRefreshSessionNotFound = &RepositoryError{Message: "refresh session not found"}
	ErrDuplicateAssignment    = &RepositoryError{Message: "duplicate asset vulnerability assignment"}
	ErrDuplicateData          = &RepositoryError{Message: "duplicate data"}
	ErrInvalidReference       = &RepositoryError{Message: "invalid reference"}
	ErrInvalidData            = &RepositoryError{Message: "invalid data"}
	ErrForbidden              = &RepositoryError{Message: "forbidden"}
	ErrCreateFailed           = &RepositoryError{Message: "create failed"}
	ErrUpdateFailed           = &RepositoryError{Message: "update failed"}
	ErrDeleteFailed           = &RepositoryError{Message: "delete failed"}
	ErrReadFailed             = &RepositoryError{Message: "read failed"}
)
