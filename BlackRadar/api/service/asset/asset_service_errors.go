package service

type ValidationError struct {
	Message string
}

func (e ValidationError) Error() string {
	return e.Message
}

type ConflictError struct {
	Message string
}

func (e ConflictError) Error() string {
	return e.Message
}

type ForbiddenError struct {
	Message string
}

func (e ForbiddenError) Error() string {
	return e.Message
}

type NotFoundError struct {
	Message string
}

func (e NotFoundError) Error() string {
	return e.Message
}

type DependencyError struct {
	Message string
}

func (e DependencyError) Error() string {
	return e.Message
}

type InternalError struct {
	Message string
}

func (e InternalError) Error() string {
	return e.Message
}

var (
	ErrInvalidAssetData              = &ValidationError{Message: "invalid asset data"}
	ErrInvalidAssetText              = &ValidationError{Message: "invalid asset text"}
	ErrInvalidAssetCVEID             = &ValidationError{Message: "invalid CVE ID"}
	ErrDuplicateAsset                = &ConflictError{Message: "asset already exists"}
	ErrDuplicateAssetVulnerability   = &ConflictError{Message: "asset vulnerability assignment already exists"}
	ErrAssetPermissionDenied         = &ForbiddenError{Message: "asset permission denied"}
	ErrVulnerabilityManagementDenied = &ForbiddenError{Message: "vulnerability management permission denied"}
	ErrAssetNotFound                 = &NotFoundError{Message: "asset not found"}
	ErrAssetVulnerabilityNotFound    = &NotFoundError{Message: "vulnerability not found"}
	ErrAssetDependency               = &DependencyError{Message: "asset dependency unavailable"}
	ErrAssetExternalService          = &DependencyError{Message: "external service unavailable"}
	ErrAssetInternal                 = &InternalError{Message: "asset service error"}
)
