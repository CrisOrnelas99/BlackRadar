package service

type AssetInvalidRequestError struct {
	Message string
}

func (e AssetInvalidRequestError) Error() string {
	return e.Message
}

var (
	ErrInvalidAssetData  = &AssetInvalidRequestError{Message: "invalid asset data"}
	ErrInvalidAssetText  = &AssetInvalidRequestError{Message: "invalid asset text"}
	ErrInvalidAssetCVEID = &AssetInvalidRequestError{Message: "invalid CVE ID"}
)

type AssetConflictError struct {
	Message string
}

func (e AssetConflictError) Error() string {
	return e.Message
}

var (
	ErrDuplicateAsset              = &AssetConflictError{Message: "asset already exists"}
	ErrDuplicateAssetVulnerability = &AssetConflictError{Message: "asset vulnerability assignment already exists"}
)

type AssetForbiddenError struct {
	Message string
}

func (e AssetForbiddenError) Error() string {
	return e.Message
}

var (
	ErrAssetPermissionDenied         = &AssetForbiddenError{Message: "asset permission denied"}
	ErrVulnerabilityManagementDenied = &AssetForbiddenError{Message: "vulnerability management permission denied"}
)

type AssetNotFoundError struct {
	Message string
}

func (e AssetNotFoundError) Error() string {
	return e.Message
}

var (
	ErrAssetNotFound              = &AssetNotFoundError{Message: "asset not found"}
	ErrAssetVulnerabilityNotFound = &AssetNotFoundError{Message: "vulnerability not found"}
)
