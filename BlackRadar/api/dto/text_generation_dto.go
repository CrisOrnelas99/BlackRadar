// Package dto defines request and response data transfer objects for the API.
package dto

// TextGenerationMessage represents a single message passed to the AI provider boundary.
type TextGenerationMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// TextGenerationResponse represents the minimal assistant output returned by the boundary.
type TextGenerationResponse struct {
	Text         string `json:"text"`
	FinishReason string `json:"finishReason,omitempty"`
}

// TextGenerationRequest wraps the prompt sent to the AI provider boundary.
type TextGenerationRequest struct {
	Model    string                  `json:"model"`
	Messages []TextGenerationMessage `json:"messages"`
}
