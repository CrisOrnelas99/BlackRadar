// Package external defines shared external-provider error sentinels.
package external

type ClientError struct {
	Message string
}

func (e ClientError) Error() string {
	return e.Message
}

var (
	ErrInvalidNVDBaseURL  = &ClientError{Message: "invalid nvd base url"}
	ErrInvalidCVEID       = &ClientError{Message: "invalid cve id"}
	ErrInvalidCVESearch   = &ClientError{Message: "invalid cve search"}
	ErrInvalidCPESearch   = &ClientError{Message: "invalid cpe search"}
	ErrCVEIDNotFound      = &ClientError{Message: "cve id not found"}
	ErrNVDRateLimited     = &ClientError{Message: "nvd rate limited"}
	ErrNVDUnavailable     = &ClientError{Message: "nvd unavailable"}
	ErrInvalidNVDResponse = &ClientError{Message: "invalid nvd response"}

	ErrInvalidOpenAIBaseURL  = &ClientError{Message: "invalid openai base url"}
	ErrInvalidOpenAIModel    = &ClientError{Message: "invalid openai model"}
	ErrMissingOpenAIAPIKey   = &ClientError{Message: "missing openai api key"}
	ErrOpenAIRateLimited     = &ClientError{Message: "openai rate limited"}
	ErrOpenAIUnavailable     = &ClientError{Message: "openai unavailable"}
	ErrInvalidOpenAIResponse = &ClientError{Message: "invalid openai response"}
)
