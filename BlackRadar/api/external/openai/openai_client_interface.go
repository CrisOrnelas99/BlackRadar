/*
Package openai interface defines the OpenAI client contract consumed by
controllers and services that need backend-owned text generation.
*/
package openai

import (
	"context"

	textgeneration "blackradar/api/service/text_generation"
)

type OpenAIClientInterface interface {
	/*
		GenerateText sends a backend-built text-generation request to the OpenAI
		Responses API and returns the assistant text output.

		Implementations must honor ctx cancellation, apply outbound timeout and
		rate-limit behavior, parse bounded provider responses, and return
		external-client sentinel errors such as ErrMissingOpenAIAPIKey,
		ErrOpenAIRateLimited, ErrOpenAIUnavailable, or ErrInvalidOpenAIResponse.

		Callers should pass only service-generated TextGenerationRequest values.
		Raw HTTP request bodies, Gin contexts, user credentials, and API keys
		should never cross this interface.
	*/
	GenerateText(ctx context.Context, request textgeneration.TextGenerationRequest) (textgeneration.TextGenerationResponse, error)
}

var _ OpenAIClientInterface = (*Client)(nil)
