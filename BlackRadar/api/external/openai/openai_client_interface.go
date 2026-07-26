package openai

import (
	"context"

	textgeneration "blackradar/api/service/text_generation"
)

type OpenAIClientInterface interface {
	GenerateText(ctx context.Context, request textgeneration.TextGenerationRequest) (textgeneration.TextGenerationResponse, error)
}

var _ OpenAIClientInterface = (*Client)(nil)
