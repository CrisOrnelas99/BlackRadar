package text_generation

import (
	"context"
)

type TextGenerationService interface {
	GenerateText(ctx context.Context, request TextGenerationRequest) (TextGenerationResponse, error)
}
