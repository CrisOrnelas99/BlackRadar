// Package openai provides a small client for the OpenAI API.
package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"blackradar/api/dto"
)

const openAIResponsesPath = "/v1/responses"

// Client submits text-generation requests to the OpenAI API.
type Client struct {
	baseURL    string
	apiKey     string
	model      string
	httpClient *http.Client
}

// NewClient creates a client with safe defaults for backend-only use.
func NewClient(baseURL string, apiKey string, model string) (*Client, error) {
	return NewClientWithHTTPClient(baseURL, apiKey, model, nil)
}

// NewClientWithHTTPClient creates a client for tests or controlled wiring.
func NewClientWithHTTPClient(baseURL string, apiKey string, model string, httpClient *http.Client) (*Client, error) {
	normalizedBaseURL, err := validateBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	normalizedModel := strings.TrimSpace(model)
	if normalizedModel == "" {
		return nil, ErrInvalidModel
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}
	return &Client{
		baseURL:    normalizedBaseURL,
		apiKey:     strings.TrimSpace(apiKey),
		model:      normalizedModel,
		httpClient: httpClient,
	}, nil
}

// GenerateText sends a prompt to OpenAI and returns the assistant text output.
func (c *Client) GenerateText(ctx context.Context, request dto.TextGenerationRequest) (dto.TextGenerationResponse, error) {
	if strings.TrimSpace(c.apiKey) == "" {
		return dto.TextGenerationResponse{}, ErrMissingAPIKey
	}
	if strings.TrimSpace(request.Model) == "" {
		request.Model = c.model
	}
	request.Model = strings.TrimSpace(request.Model)
	if request.Model == "" {
		return dto.TextGenerationResponse{}, ErrInvalidModel
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
		return dto.TextGenerationResponse{}, ErrInvalidOpenAIReply
	}

	text := strings.TrimSpace(payloadResponse.OutputText)
	if text == "" {
		text = strings.TrimSpace(firstOutputText(payloadResponse.Output))
	}
	if text == "" {
		return dto.TextGenerationResponse{}, ErrInvalidOpenAIReply
	}

	return dto.TextGenerationResponse{
		Text:         text,
		FinishReason: strings.TrimSpace(payloadResponse.Status),
	}, nil
}

func validateBaseURL(baseURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", ErrInvalidBaseURL
	}
	if parsed.Path != openAIResponsesPath {
		return "", ErrInvalidBaseURL
	}
	if parsed.Scheme == "https" {
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return parsed.String(), nil
	}
	if parsed.Scheme == "http" && isLocalHost(parsed.Hostname()) {
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return parsed.String(), nil
	}
	return "", ErrInvalidBaseURL
}

func isLocalHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

func toResponsesRequest(request dto.TextGenerationRequest) openAIResponsesRequest {
	input := make([]openAIInputMessage, 0, len(request.Messages))
	instructions := make([]string, 0, 1)
	for _, message := range request.Messages {
		role := strings.TrimSpace(message.Role)
		content := strings.TrimSpace(message.Content)
		if role == "" || content == "" {
			continue
		}
		if role == "system" {
			instructions = append(instructions, content)
			continue
		}
		input = append(input, openAIInputMessage{
			Role: role,
			Content: []openAIInputContent{
				{
					Type: "input_text",
					Text: content,
				},
			},
		})
	}

	return openAIResponsesRequest{
		Model:           request.Model,
		Instructions:    strings.Join(instructions, "\n\n"),
		Input:           input,
		Store:           false,
		MaxOutputTokens: 1000,
	}
}

func firstOutputText(output []openAIOutputItem) string {
	for _, item := range output {
		for _, content := range item.Content {
			if content.Text != "" {
				return content.Text
			}
		}
	}
	return ""
}

type openAIResponsesRequest struct {
	Model           string               `json:"model"`
	Instructions    string               `json:"instructions,omitempty"`
	Input           []openAIInputMessage `json:"input"`
	Store           bool                 `json:"store"`
	MaxOutputTokens int                  `json:"max_output_tokens,omitempty"`
}

type openAIInputMessage struct {
	Role    string               `json:"role"`
	Content []openAIInputContent `json:"content"`
}

type openAIInputContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type openAIResponsesResponse struct {
	Status     string             `json:"status"`
	OutputText string             `json:"output_text"`
	Output     []openAIOutputItem `json:"output"`
}

type openAIOutputItem struct {
	Content []openAIOutputContent `json:"content"`
}

type openAIOutputContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
