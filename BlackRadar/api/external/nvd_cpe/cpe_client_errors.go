// Package cpeclient errors defines sentinel errors returned by the NVD CPE client.
package cpeclient

// CPEClientError identifies an NVD CPE client failure category.
type CPEClientError struct {
	Message string
}

// Error returns the NVD CPE client error message.
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
