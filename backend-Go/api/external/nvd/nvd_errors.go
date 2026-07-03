// Package nvd provides a small client for the official NVD CVE API.
package nvd

type NVDClientError struct {
	Message string
}

func (e NVDClientError) Error() string {
	return e.Message
}

var (
	ErrInvalidBaseURL     = &NVDClientError{Message: "invalid nvd base url"}
	ErrInvalidCVEID       = &NVDClientError{Message: "invalid cve id"}
	ErrInvalidCVESearch   = &NVDClientError{Message: "invalid cve search"}
	ErrInvalidCPESearch   = &NVDClientError{Message: "invalid cpe search"}
	ErrCVEIDNotFound      = &NVDClientError{Message: "cve id not found"}
	ErrNVDRateLimited     = &NVDClientError{Message: "nvd rate limited"}
	ErrNVDUnavailable     = &NVDClientError{Message: "nvd unavailable"}
	ErrInvalidNVDResponse = &NVDClientError{Message: "invalid nvd response"}
)
