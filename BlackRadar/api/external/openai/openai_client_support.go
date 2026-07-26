// Package openai support maps application text-generation requests to OpenAI
// API contracts and validates outbound endpoint configuration.
package openai

import (
	"net/url"
	"strings"

	dto "blackradar/api/service/text_generation"
)

// validateBaseURL validates and normalizes the allowed OpenAI responses endpoint.
func validateBaseURL(baseURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", ErrInvalidOpenAIBaseURL
	}
	if parsed.Path != openAIResponsesPath {
		return "", ErrInvalidOpenAIBaseURL
	}
	if parsed.Scheme == "https" && parsed.Host == officialOpenAIHost {
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return parsed.String(), nil
	}
	if parsed.Scheme == "http" && isLocalHost(parsed.Hostname()) {
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return parsed.String(), nil
	}
	return "", ErrInvalidOpenAIBaseURL
}

// isLocalHost reports whether a host is allowed for local test wiring.
func isLocalHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

// toResponsesRequest converts the application text request into OpenAI's responses payload.
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
		if role != "user" && role != "assistant" && role != "developer" {
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

// firstOutputText extracts the first text output from a structured responses payload.
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
