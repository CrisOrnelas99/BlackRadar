// Package openai verifies the OpenAI API client and request wiring.
package openai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"secureops/backend-go/api/dto"
)

func TestClientGenerateText(t *testing.T) {
	var receivedAuth string
	var receivedRequest openAIResponsesRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != openAIResponsesPath {
			t.Fatalf("expected path %s, got %s", openAIResponsesPath, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&receivedRequest); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"completed","output":[{"content":[{"type":"output_text","text":"ranked match"}]}]}`))
	}))
	defer server.Close()

	client, err := NewClientWithHTTPClient(server.URL+openAIResponsesPath, "test-key", "gpt-4.1-mini", server.Client())
	if err != nil {
		t.Fatalf("expected client creation to succeed, got %v", err)
	}

	response, err := client.GenerateText(context.Background(), dto.TextGenerationRequest{
		Messages: []dto.TextGenerationMessage{
			{Role: "system", Content: "Return JSON only."},
			{Role: "user", Content: "rank these candidates"},
		},
	})
	if err != nil {
		t.Fatalf("expected generate text to succeed, got %v", err)
	}
	if receivedAuth != "Bearer test-key" {
		t.Fatalf("expected auth header to be set, got %q", receivedAuth)
	}
	if receivedRequest.Model != "gpt-4.1-mini" {
		t.Fatalf("expected configured model, got %q", receivedRequest.Model)
	}
	if receivedRequest.Store {
		t.Fatal("expected provider request storage to be disabled")
	}
	if receivedRequest.Instructions != "Return JSON only." {
		t.Fatalf("expected system prompt to map to instructions, got %q", receivedRequest.Instructions)
	}
	if len(receivedRequest.Input) != 1 || receivedRequest.Input[0].Role != "user" {
		t.Fatalf("expected one user input message, got %#v", receivedRequest.Input)
	}
	if response.Text != "ranked match" {
		t.Fatalf("expected response text ranked match, got %q", response.Text)
	}
	if response.FinishReason != "completed" {
		t.Fatalf("expected finish reason completed, got %q", response.FinishReason)
	}
}

func TestClientGenerateTextUsesOutputTextShortcut(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"completed","output_text":"shortcut text"}`))
	}))
	defer server.Close()

	client, err := NewClientWithHTTPClient(server.URL+openAIResponsesPath, "test-key", "gpt-4.1-mini", server.Client())
	if err != nil {
		t.Fatalf("expected client creation to succeed, got %v", err)
	}

	response, err := client.GenerateText(context.Background(), dto.TextGenerationRequest{
		Messages: []dto.TextGenerationMessage{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("expected generate text to succeed, got %v", err)
	}
	if response.Text != "shortcut text" {
		t.Fatalf("expected shortcut text, got %q", response.Text)
	}
}
