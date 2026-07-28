package ai

import (
	"context"
	"errors"
	"testing"

	textgenerationservice "blackradar/api/service/text_generation"
)

func TestSendMessageRejectsInvalidMessage(t *testing.T) {
	service := NewAIService(&fakeAIClient{})

	_, err := service.SendMessage(context.Background(), "   ")
	if !errors.Is(err, ErrInvalidAIMessage) {
		t.Fatalf("expected invalid AI message error, got %v", err)
	}
}

func TestSendMessageTrimsMessageBeforeBuildingRequest(t *testing.T) {
	client := &fakeAIClient{
		response: textgenerationservice.TextGenerationResponse{Text: "response"},
	}
	service := NewAIService(client)

	_, err := service.SendMessage(context.Background(), "  Say hello.  ")
	if err != nil {
		t.Fatalf("expected message to succeed, got %v", err)
	}
	if len(client.request.Messages) != 2 {
		t.Fatalf("expected system and user messages, got %d", len(client.request.Messages))
	}
	if client.request.Messages[1].Content != "Say hello." {
		t.Fatalf("expected trimmed message, got %q", client.request.Messages[1].Content)
	}
}

func TestTestProviderRejectsMissingProvider(t *testing.T) {
	service := NewAIService(nil)

	_, err := service.TestProvider(context.Background())
	if !errors.Is(err, ErrAIProviderUnavailable) {
		t.Fatalf("expected missing provider error, got %v", err)
	}
}

type fakeAIClient struct {
	request  textgenerationservice.TextGenerationRequest
	response textgenerationservice.TextGenerationResponse
}

func (f *fakeAIClient) GenerateText(_ context.Context, request textgenerationservice.TextGenerationRequest) (textgenerationservice.TextGenerationResponse, error) {
	f.request = request
	return f.response, nil
}
