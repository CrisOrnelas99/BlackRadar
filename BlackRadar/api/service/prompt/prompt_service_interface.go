package service

import (
	"context"
)

type TextGenerationService interface {
	GenerateText(ctx context.Context, request TextGenerationRequest) (TextGenerationResponse, error)
}
