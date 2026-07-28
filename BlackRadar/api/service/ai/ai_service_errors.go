// Package ai errors defines AI service error categories.
package ai

// ValidationError identifies invalid AI service input.
type ValidationError struct {
	Message string
}

// Error returns the validation error message.
func (e ValidationError) Error() string {
	return e.Message
}

// DependencyError identifies an unavailable AI provider dependency.
type DependencyError struct {
	Message string
}

// Error returns the dependency error message.
func (e DependencyError) Error() string {
	return e.Message
}

var (
	ErrInvalidAIMessage      = &ValidationError{Message: "message must be between 1 and 1000 characters"}
	ErrAIProviderUnavailable = &DependencyError{Message: "AI provider unavailable"}
)
