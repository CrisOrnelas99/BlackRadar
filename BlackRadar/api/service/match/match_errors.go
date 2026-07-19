package match

type MatchInvalidRequestError struct {
	Message string
}

func (e MatchInvalidRequestError) Error() string {
	return e.Message
}

var (
	ErrInvalidCVEID = &MatchInvalidRequestError{Message: "invalid CVE ID"}
)

type MatchNotFoundError struct {
	Message string
}

func (e MatchNotFoundError) Error() string {
	return e.Message
}

var (
	ErrCVENotFound = &MatchNotFoundError{Message: "CVE not found"}
)

type MatchRateLimitedError struct {
	Message string
}

func (e MatchRateLimitedError) Error() string {
	return e.Message
}

var (
	ErrNVDLookupRateLimited = &MatchRateLimitedError{Message: "NVD lookup rate limited"}
)

type MatchExternalServiceError struct {
	Message string
}

func (e MatchExternalServiceError) Error() string {
	return e.Message
}

var (
	ErrMatchExternalService = &MatchExternalServiceError{Message: "external service unavailable"}
)

type MatchInternalError struct {
	Message string
}

func (e MatchInternalError) Error() string {
	return e.Message
}

var (
	ErrMatchInternal = &MatchInternalError{Message: "match service error"}
)
