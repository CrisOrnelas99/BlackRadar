package asset_match

type ValidationError struct {
	Message string
}

func (e ValidationError) Error() string {
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
	ErrInvalidCVEID         = &ValidationError{Message: "invalid CVE ID"}
	ErrCVENotFound          = &NotFoundError{Message: "CVE not found"}
	ErrNVDLookupRateLimited = &DependencyError{Message: "NVD lookup rate limited"}
	ErrMatchDependency      = &DependencyError{Message: "match dependency unavailable"}
	ErrMatchExternalService = &DependencyError{Message: "external service unavailable"}
	ErrMatchInternal        = &InternalError{Message: "match service error"}
)
