// Package ai provides application services for backend-only AI workflows.
package ai

import (
	"context"
	"errors"

	openaiexternal "blackradar/api/external/openai"
	textgenerationservice "blackradar/api/service/text_generation"
)

// aiServiceImpl implements backend-only AI workflows.
type aiServiceImpl struct {
	textAI                openaiexternal.OpenAIClientInterface
	textGeneration        textgenerationservice.TextGenerationService
	dashboardRepositories DashboardRepositories
}

// NewAIService creates an AI service backed by the supplied provider client.
func NewAIService(textAI openaiexternal.OpenAIClientInterface, dashboardRepositories ...DashboardRepositories) *aiServiceImpl {
	service := &aiServiceImpl{
		textAI:         textAI,
		textGeneration: textgenerationservice.NewTextGenerationService(),
	}
	if len(dashboardRepositories) > 0 {
		service.dashboardRepositories = dashboardRepositories[0]
	}
	return service
}

// TestProvider sends a fixed prompt to the configured AI provider.
func (s *aiServiceImpl) TestProvider(ctx context.Context) (textgenerationservice.TextGenerationResponse, error) {
	if s.textAI == nil {
		return textgenerationservice.TextGenerationResponse{}, ErrAIProviderUnavailable
	}

	response, err := s.textAI.GenerateText(ctx, s.textGeneration.BuildDiagnosticRequest())
	if err != nil {
		return textgenerationservice.TextGenerationResponse{}, errors.Join(ErrAIProviderUnavailable, err)
	}

	return response, nil
}
