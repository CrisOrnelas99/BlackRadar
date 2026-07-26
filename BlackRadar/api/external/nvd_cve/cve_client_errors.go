package cveclient

type CVEClientError struct {
	Message string
}

func (e CVEClientError) Error() string {
	return e.Message
}

var (
	ErrInvalidNVDBaseURL  = &CVEClientError{Message: "invalid nvd base url"}
	ErrInvalidCVEID       = &CVEClientError{Message: "invalid cve id"}
	ErrInvalidCVESearch   = &CVEClientError{Message: "invalid cve search"}
	ErrInvalidCPESearch   = &CVEClientError{Message: "invalid cpe search"}
	ErrCVEIDNotFound      = &CVEClientError{Message: "cve id not found"}
	ErrNVDRateLimited     = &CVEClientError{Message: "nvd rate limited"}
	ErrNVDUnavailable     = &CVEClientError{Message: "nvd unavailable"}
	ErrInvalidNVDResponse = &CVEClientError{Message: "invalid nvd response"}
)
