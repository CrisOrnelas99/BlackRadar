// Package cveclient errors defines sentinel errors returned by the NVD CVE client.
package cveclient

// CVEClientError identifies an NVD CVE client failure category.
type CVEClientError struct {
	Message string
}

// Error returns the NVD CVE client error message.
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
