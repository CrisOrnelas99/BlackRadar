// Package ai provides application services for backend-only AI diagnostic workflows.
package ai

import (
	"context"
	"errors"
	"strings"

	openaiexternal "blackradar/api/external/openai"
	textgenerationservice "blackradar/api/service/text_generation"
)

const maxTemporaryAIMessageLength = 1000

// aiServiceImpl implements backend-only AI diagnostic workflows.
type aiServiceImpl struct {
	textAI         openaiexternal.OpenAIClientInterface
	textGeneration textgenerationservice.TextGenerationService
}

// NewAIService creates an AI service backed by the supplied provider client.
func NewAIService(textAI openaiexternal.OpenAIClientInterface) *aiServiceImpl {
	return &aiServiceImpl{
		textAI:         textAI,
		textGeneration: textgenerationservice.NewTextGenerationService(),
	}
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

// SendMessage sends a bounded administrator diagnostic message to the configured AI provider.
func (s *aiServiceImpl) SendMessage(ctx context.Context, message string) (textgenerationservice.TextGenerationResponse, error) {
	message = strings.TrimSpace(message)
	if message == "" || len(message) > maxTemporaryAIMessageLength {
		return textgenerationservice.TextGenerationResponse{}, ErrInvalidAIMessage
	}
	if s.textAI == nil {
		return textgenerationservice.TextGenerationResponse{}, ErrAIProviderUnavailable
	}

	response, err := s.textAI.GenerateText(ctx, s.textGeneration.BuildTemporaryMessageRequest(message))
	if err != nil {
		return textgenerationservice.TextGenerationResponse{}, errors.Join(ErrAIProviderUnavailable, err)
	}

	return response, nil
}
