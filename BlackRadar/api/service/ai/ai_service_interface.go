/*
Package ai provides application services for backend-only AI diagnostic workflows.
*/
package ai

import (
	"context"

	textgenerationservice "blackradar/api/service/text_generation"
)

// AIService defines the provider-backed diagnostic workflows exposed by the API.
type AIService interface {
	/*
		TestProvider sends the fixed diagnostic request to the configured provider.

		Implementations must use a backend-owned prompt and return a dependency
		error when the provider is unavailable or not configured.
	*/
	TestProvider(ctx context.Context) (textgenerationservice.TextGenerationResponse, error)

	/*
		SendMessage sends a bounded administrator diagnostic message to the
		configured provider.

		Implementations must validate the message before creating the provider
		request and must preserve the locked prompt boundary around user content.
	*/
	SendMessage(ctx context.Context, message string) (textgenerationservice.TextGenerationResponse, error)
}
