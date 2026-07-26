// Package openai errors defines sentinel errors returned by the OpenAI client.
package openai

// OpenAIClientError identifies an OpenAI client failure category.
type OpenAIClientError struct {
	Message string
}

// Error returns the OpenAI client error message.
func (e OpenAIClientError) Error() string {
	return e.Message
}

var (
	ErrInvalidOpenAIBaseURL  = &OpenAIClientError{Message: "invalid openai base url"}
	ErrInvalidOpenAIModel    = &OpenAIClientError{Message: "invalid openai model"}
	ErrMissingOpenAIAPIKey   = &OpenAIClientError{Message: "missing openai api key"}
	ErrOpenAIRateLimited     = &OpenAIClientError{Message: "openai rate limited"}
	ErrOpenAIUnavailable     = &OpenAIClientError{Message: "openai unavailable"}
	ErrInvalidOpenAIResponse = &OpenAIClientError{Message: "invalid openai response"}
)
