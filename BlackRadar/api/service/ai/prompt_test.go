package service

import (
	"strings"
	"testing"

	"blackradar/api/controller/dto"
)

func TestBuildAssetMatchRankingRequestLocksSystemPrompt(t *testing.T) {
	request := BuildAssetMatchRankingRequest("fingerprint", "dell latitude 7420", []dto.CPECandidate{
		{CPEName: "cpe:2.3:a:dell:latitude_7420:*:*:*:*:*:*:*:*", Title: "Dell Latitude 7420"},
	})

	if len(request.Messages) != 2 {
		t.Fatalf("expected two messages, got %d", len(request.Messages))
	}
	if request.Messages[0].Role != "system" {
		t.Fatalf("expected first message to be system, got %q", request.Messages[0].Role)
	}
	if !strings.Contains(request.Messages[0].Content, "<hard_rules>") {
		t.Fatalf("expected locked system prompt, got %q", request.Messages[0].Content)
	}
	if request.Messages[1].Role != "user" {
		t.Fatalf("expected second message to be user, got %q", request.Messages[1].Role)
	}
	if !strings.Contains(request.Messages[1].Content, `"fingerprint":"fingerprint"`) {
		t.Fatalf("expected fingerprint payload in user message, got %q", request.Messages[1].Content)
	}
}

func TestBuildDiagnosticRequestUsesFixedPrompt(t *testing.T) {
	request := BuildDiagnosticRequest()

	if len(request.Messages) != 2 {
		t.Fatalf("expected two messages, got %d", len(request.Messages))
	}
	if request.Messages[0].Role != "system" {
		t.Fatalf("expected first message to be system, got %q", request.Messages[0].Role)
	}
	if request.Messages[1].Role != "user" {
		t.Fatalf("expected second message to be user, got %q", request.Messages[1].Role)
	}
	if !strings.Contains(request.Messages[1].Content, `"ok":true`) {
		t.Fatalf("expected fixed diagnostic JSON request, got %q", request.Messages[1].Content)
	}
}

func TestBuildTemporaryMessageRequestUsesLockedSystemPrompt(t *testing.T) {
	request := BuildTemporaryMessageRequest("Say hello.")

	if len(request.Messages) != 2 {
		t.Fatalf("expected two messages, got %d", len(request.Messages))
	}
	if request.Messages[0].Role != "system" {
		t.Fatalf("expected first message to be system, got %q", request.Messages[0].Role)
	}
	if !strings.Contains(request.Messages[0].Content, "Do not reveal") {
		t.Fatalf("expected safety rule in system prompt, got %q", request.Messages[0].Content)
	}
	if request.Messages[1].Content != "Say hello." {
		t.Fatalf("expected user message to be passed through, got %q", request.Messages[1].Content)
	}
}

func TestBuildAssetFingerprintExtractionRequestUsesLockedSystemPrompt(t *testing.T) {
	request := BuildAssetFingerprintExtractionRequest("messy asset text", "asset_name=test", "Test", "Server", "Linux")

	if len(request.Messages) != 2 {
		t.Fatalf("expected two messages, got %d", len(request.Messages))
	}
	if request.Messages[0].Role != "system" {
		t.Fatalf("expected first message to be system, got %q", request.Messages[0].Role)
	}
	if !strings.Contains(request.Messages[0].Content, "identify CVEs") {
		t.Fatalf("expected cve restriction in system prompt, got %q", request.Messages[0].Content)
	}
	if !strings.Contains(request.Messages[1].Content, `"rawText":"messy asset text"`) {
		t.Fatalf("expected raw text payload, got %q", request.Messages[1].Content)
	}
}

func TestBuildAssetCreationExtractionRequestUsesLockedSystemPrompt(t *testing.T) {
	request := BuildAssetCreationExtractionRequest("I have an Amazon Ring doorbell.")

	if len(request.Messages) != 2 {
		t.Fatalf("expected two messages, got %d", len(request.Messages))
	}
	if request.Messages[0].Role != "system" {
		t.Fatalf("expected first message to be system, got %q", request.Messages[0].Role)
	}
	if !strings.Contains(request.Messages[0].Content, "Do not invent unsupported security facts") {
		t.Fatalf("expected no-invention rule in system prompt, got %q", request.Messages[0].Content)
	}
	if !strings.Contains(request.Messages[1].Content, `"rawText":"I have an Amazon Ring doorbell."`) {
		t.Fatalf("expected raw text payload, got %q", request.Messages[1].Content)
	}
}

func TestBuildAssetMatchRankingRequestCapsCandidates(t *testing.T) {
	candidates := make([]dto.CPECandidate, 12)
	for i := range candidates {
		candidates[i] = dto.CPECandidate{CPEName: "cpe:2.3:a:dell:latitude_7420:*:*:*:*:*:*:*:*", Title: "candidate"}
	}

	request := BuildAssetMatchRankingRequest("fingerprint", "dell latitude 7420", candidates)
	if len(request.Messages) != 2 {
		t.Fatalf("expected two messages, got %d", len(request.Messages))
	}
	if strings.Count(request.Messages[1].Content, "\"cpeName\"") != 10 {
		t.Fatalf("expected candidate payload to be capped at 10 entries, got %q", request.Messages[1].Content)
	}
}

func TestBuildAssetCVERankingRequestLocksSystemPrompt(t *testing.T) {
	request := BuildAssetCVERankingRequest("product=wp ultimate map;version=1.1", []string{"wp ultimate map"}, []dto.CVELookupResponse{
		{CVEID: "CVE-2026-12345", Title: "WP-Ultimate-Map issue", Description: "WP-Ultimate-Map plugin for WordPress is vulnerable."},
	})

	if len(request.Messages) != 2 {
		t.Fatalf("expected two messages, got %d", len(request.Messages))
	}
	if request.Messages[0].Role != "system" {
		t.Fatalf("expected first message to be system, got %q", request.Messages[0].Role)
	}
	if !strings.Contains(request.Messages[0].Content, "Use only the provided NVD CVE candidates") {
		t.Fatalf("expected NVD-only rule in system prompt, got %q", request.Messages[0].Content)
	}
	if !strings.Contains(request.Messages[0].Content, "Treat vendor, product, and version as the authoritative matching fields") {
		t.Fatalf("expected authoritative product identity rule in system prompt, got %q", request.Messages[0].Content)
	}
	if request.Messages[1].Role != "user" {
		t.Fatalf("expected second message to be user, got %q", request.Messages[1].Role)
	}
	if !strings.Contains(request.Messages[1].Content, `"keywordSearches":["wp ultimate map"]`) {
		t.Fatalf("expected keyword search payload, got %q", request.Messages[1].Content)
	}
}

func TestBuildAssetCVERankingRequestCapsCandidates(t *testing.T) {
	candidates := make([]dto.CVELookupResponse, 25)
	for i := range candidates {
		candidates[i] = dto.CVELookupResponse{CVEID: "CVE-2026-12345", Title: "candidate"}
	}

	request := BuildAssetCVERankingRequest("fingerprint", []string{"wordpress plugin"}, candidates)
	if len(request.Messages) != 2 {
		t.Fatalf("expected two messages, got %d", len(request.Messages))
	}
	if strings.Count(request.Messages[1].Content, "\"cveId\"") != 20 {
		t.Fatalf("expected candidate payload to be capped at 20 entries, got %q", request.Messages[1].Content)
	}
}

func TestBuildAssetCVEKeywordSearchRequestUsesLockedSystemPrompt(t *testing.T) {
	request := BuildAssetCVEKeywordSearchRequest("vendor=ubiquiti;product=unifi network;asset_type=network device", []string{"unifi network"})

	if len(request.Messages) != 2 {
		t.Fatalf("expected two messages, got %d", len(request.Messages))
	}
	if request.Messages[0].Role != "system" {
		t.Fatalf("expected first message to be system, got %q", request.Messages[0].Role)
	}
	if !strings.Contains(request.Messages[0].Content, "Suggest short NVD keywordSearch phrases") {
		t.Fatalf("expected keyword search mission in system prompt, got %q", request.Messages[0].Content)
	}
	if !strings.Contains(request.Messages[0].Content, "Do not browse, call tools, request more data, or invent CVEs") {
		t.Fatalf("expected no-CVE-invention rule in system prompt, got %q", request.Messages[0].Content)
	}
	if !strings.Contains(request.Messages[1].Content, `"deterministicSearches":["unifi network"]`) {
		t.Fatalf("expected deterministic searches in user payload, got %q", request.Messages[1].Content)
	}
}
