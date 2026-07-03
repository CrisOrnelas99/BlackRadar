// Package openai provides a small client for the OpenAI API.
package openai

type OpenAIClientError struct {
	Message string
}

func (e OpenAIClientError) Error() string {
	return e.Message
}

var (
	ErrInvalidBaseURL     = &OpenAIClientError{Message: "invalid openai base url"}
	ErrInvalidModel       = &OpenAIClientError{Message: "invalid openai model"}
	ErrMissingAPIKey      = &OpenAIClientError{Message: "missing openai api key"}
	ErrOpenAIUnavailable  = &OpenAIClientError{Message: "openai unavailable"}
	ErrInvalidOpenAIReply = &OpenAIClientError{Message: "invalid openai response"}
)
