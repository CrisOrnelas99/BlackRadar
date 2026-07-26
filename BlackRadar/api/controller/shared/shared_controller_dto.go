// Package shared dto defines common API response contracts.
package shared

// ErrorResponse is the safe error envelope returned to API clients.
type ErrorResponse struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"requestId"`
}
