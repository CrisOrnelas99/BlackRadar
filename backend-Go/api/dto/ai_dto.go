// Package dto defines request and response data transfer objects for the API.
package dto

// AITestResponse exposes a safe AI provider connectivity test result.
type AITestResponse struct {
	Status       string `json:"status"`
	Provider     string `json:"provider"`
	ResponseText string `json:"responseText"`
	FinishReason string `json:"finishReason,omitempty"`
}

// AIMessageRequest captures a temporary admin-only diagnostic message for the AI provider.
type AIMessageRequest struct {
	Message string `json:"message"`
}

// AIMessageResponse exposes the configured AI provider's response.
type AIMessageResponse struct {
	Provider     string `json:"provider"`
	ResponseText string `json:"responseText"`
	FinishReason string `json:"finishReason,omitempty"`
}
