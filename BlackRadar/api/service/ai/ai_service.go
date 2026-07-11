// Package service provides AI orchestration interfaces used by the backend.
package service

import (
	"context"

	"blackradar/api/controller/dto"
)

// TextGenerationService defines the minimal contract used for backend AI work.
type TextGenerationService interface {
	// GenerateText submits a prompt and returns the model output.
	GenerateText(ctx context.Context, request dto.TextGenerationRequest) (dto.TextGenerationResponse, error)
}
