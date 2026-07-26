// Package openai provides a small client for the OpenAI API.
package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	externalratelimiter "blackradar/api/external/rate_limiter"
	dto "blackradar/api/service/text_generation"
)

const openAIResponsesPath = "/v1/responses"
const defaultOpenAIRateLimitWindow = time.Minute
const officialOpenAIHost = "api.openai.com"

// Client submits text-generation requests to the OpenAI API.
type Client struct {
	baseURL    string
	apiKey     string
	model      string
	httpClient *http.Client
	limiter    *externalratelimiter.RateLimiter
}

// NewClient creates a client with safe defaults for backend-only use.
func NewClient(baseURL string, apiKey string, model string) (*Client, error) {
	return NewClientWithHTTPClient(baseURL, apiKey, model, nil, nil)
}

// NewClientWithHTTPClient creates a client for tests or controlled wiring.
func NewClientWithHTTPClient(baseURL string, apiKey string, model string, httpClient *http.Client, limiter *externalratelimiter.RateLimiter) (*Client, error) {
	normalizedBaseURL, err := validateBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	normalizedModel := strings.TrimSpace(model)
	if normalizedModel == "" {
		return nil, ErrInvalidOpenAIModel
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}
	if limiter == nil {
		limiter = externalratelimiter.NewRateLimiter(30, defaultOpenAIRateLimitWindow)
	}
	return &Client{
		baseURL:    normalizedBaseURL,
		apiKey:     strings.TrimSpace(apiKey),
		model:      normalizedModel,
		httpClient: httpClient,
		limiter:    limiter,
	}, nil
}

// GenerateText sends a prompt to OpenAI and returns the assistant text output.
func (c *Client) GenerateText(ctx context.Context, request dto.TextGenerationRequest) (dto.TextGenerationResponse, error) {
	if strings.TrimSpace(c.apiKey) == "" {
		return dto.TextGenerationResponse{}, ErrMissingOpenAIAPIKey
	}
	if strings.TrimSpace(request.Model) == "" {
		request.Model = c.model
	}
	request.Model = strings.TrimSpace(request.Model)
	if request.Model == "" {
		return dto.TextGenerationResponse{}, ErrInvalidOpenAIModel
	}
	if c.limiter != nil && !c.limiter.Allow(time.Now()) {
		return dto.TextGenerationResponse{}, ErrOpenAIRateLimited
	}

	payload, err := json.Marshal(toResponsesRequest(request))
	if err != nil {
		return dto.TextGenerationResponse{}, fmt.Errorf("%w: encode request", ErrOpenAIUnavailable)
	}

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(payload))
	if err != nil {
		return dto.TextGenerationResponse{}, fmt.Errorf("%w: build request", ErrOpenAIUnavailable)
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+c.apiKey)

	response, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return dto.TextGenerationResponse{}, fmt.Errorf("%w: request failed", ErrOpenAIUnavailable)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return dto.TextGenerationResponse{}, fmt.Errorf("%w: status %d", ErrOpenAIUnavailable, response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return dto.TextGenerationResponse{}, fmt.Errorf("%w: read response", ErrOpenAIUnavailable)
	}

	var payloadResponse openAIResponsesResponse
	if err := json.Unmarshal(body, &payloadResponse); err != nil {
		return dto.TextGenerationResponse{}, ErrInvalidOpenAIResponse
	}

	text := strings.TrimSpace(payloadResponse.OutputText)
	if text == "" {
		text = strings.TrimSpace(firstOutputText(payloadResponse.Output))
	}
	if text == "" {
		return dto.TextGenerationResponse{}, ErrInvalidOpenAIResponse
	}

	return dto.TextGenerationResponse{
		Text:         text,
		FinishReason: strings.TrimSpace(payloadResponse.Status),
	}, nil
}
