package cpeclient

type CPEClientError struct {
	Message string
}

func (e CPEClientError) Error() string {
	return e.Message
}

var (
	ErrInvalidNVDBaseURL  = &CPEClientError{Message: "invalid nvd base url"}
	ErrInvalidCPESearch   = &CPEClientError{Message: "invalid cpe search"}
	ErrNVDRateLimited     = &CPEClientError{Message: "nvd rate limited"}
	ErrNVDUnavailable     = &CPEClientError{Message: "nvd unavailable"}
	ErrInvalidNVDResponse = &CPEClientError{Message: "invalid nvd response"}
)
