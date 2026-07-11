// Package controller tests AI diagnostic controller request handling.
package controller

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"blackradar/api/controller/dto"
	appcontext "blackradar/api/requestContext"
	aiservice "blackradar/api/service/ai"
)

func TestAIControllerTestProvider(t *testing.T) {
	controller := NewAIController(&fakeTextGenerationService{
		response: dto.TextGenerationResponse{Text: `{"ok":true,"message":"ai provider reachable"}`, FinishReason: "stop"},
	})
	ec, recorder := newAIControllerContext(t)

	controller.TestProvider(ec)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	var response dto.AITestResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Status != "ok" {
		t.Fatalf("expected status ok, got %q", response.Status)
	}
	if response.Provider != "openai" {
		t.Fatalf("expected provider openai, got %q", response.Provider)
	}
	if response.ResponseText == "" {
		t.Fatal("expected response text")
	}
}

func TestAIControllerTestProviderMapsProviderError(t *testing.T) {
	controller := NewAIController(&fakeTextGenerationService{err: errors.New("provider unavailable")})
	ec, recorder := newAIControllerContext(t)

	controller.TestProvider(ec)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected status %d, got %d", http.StatusBadGateway, recorder.Code)
	}
	var response dto.ErrorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Code != "UPSTREAM_ERROR" {
		t.Fatalf("expected upstream error, got %q", response.Code)
	}
}

func TestAIControllerSendMessage(t *testing.T) {
	controller := NewAIController(&fakeTextGenerationService{
		response: dto.TextGenerationResponse{Text: "Hello from OpenAI.", FinishReason: "completed"},
	})
	ec, recorder := newAIMessageControllerContext(t, `{"message":"Say hello."}`)

	controller.SendMessage(ec)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	var response dto.AIMessageResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Provider != "openai" {
		t.Fatalf("expected provider openai, got %q", response.Provider)
	}
	if response.ResponseText != "Hello from OpenAI." {
		t.Fatalf("expected OpenAI response text, got %q", response.ResponseText)
	}
}

func TestAIControllerSendMessageRejectsBlankMessage(t *testing.T) {
	controller := NewAIController(&fakeTextGenerationService{})
	ec, recorder := newAIMessageControllerContext(t, `{"message":"  "}`)

	controller.SendMessage(ec)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}
}

type fakeTextGenerationService struct {
	response dto.TextGenerationResponse
	err      error
}

func (f *fakeTextGenerationService) GenerateText(ctx context.Context, request dto.TextGenerationRequest) (dto.TextGenerationResponse, error) {
	if f.err != nil {
		return dto.TextGenerationResponse{}, f.err
	}
	return f.response, nil
}

var _ aiservice.TextGenerationService = (*fakeTextGenerationService)(nil)

func newAIControllerContext(t *testing.T) (*appcontext.GinContext, *httptest.ResponseRecorder) {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/ai/test", nil)
	ec := appcontext.NewGinContext(ctx, "txn-123", slog.New(slog.NewTextHandler(io.Discard, nil)))
	appcontext.SetGinContext(ctx, ec)
	return ec, recorder
}

func newAIMessageControllerContext(t *testing.T, body string) (*appcontext.GinContext, *httptest.ResponseRecorder) {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/ai/message", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ec := appcontext.NewGinContext(ctx, "txn-123", slog.New(slog.NewTextHandler(io.Discard, nil)))
	appcontext.SetGinContext(ctx, ec)
	return ec, recorder
}
