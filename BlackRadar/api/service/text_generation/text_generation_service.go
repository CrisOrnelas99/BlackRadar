// Package text_generation provides locked AI text-generation request builders used by the backend.
package text_generation

import (
	cpeclient "blackradar/api/external/nvd_cpe"
	cveclient "blackradar/api/external/nvd_cve"
)

// textGenerationServiceImpl implements safe text-generation request builders.
type textGenerationServiceImpl struct{}

var _ TextGenerationService = textGenerationServiceImpl{}

// NewTextGenerationService creates a text-generation request builder service.
func NewTextGenerationService() TextGenerationService {
	return textGenerationServiceImpl{}
}

// BuildDiagnosticRequest constructs a fixed prompt used only for provider connectivity testing.
func (textGenerationServiceImpl) BuildDiagnosticRequest() TextGenerationRequest {
	return BuildDiagnosticRequest()
}

// BuildDiagnosticRequest constructs a fixed prompt used only for provider connectivity testing.
func BuildDiagnosticRequest() TextGenerationRequest {
	return TextGenerationRequest{
		Messages: []TextGenerationMessage{
			{
				Role:    "system",
				Content: aiDiagnosticSystemPrompt,
			},
			{
				Role:    "user",
				Content: `Return exactly: {"ok":true,"message":"ai provider reachable"}`,
			},
		},
	}
}

// BuildTemporaryMessageRequest constructs a temporary admin-only diagnostic prompt.
func (textGenerationServiceImpl) BuildTemporaryMessageRequest(message string) TextGenerationRequest {
	return BuildTemporaryMessageRequest(message)
}

// BuildTemporaryMessageRequest constructs a temporary admin-only diagnostic prompt.
func BuildTemporaryMessageRequest(message string) TextGenerationRequest {
	return TextGenerationRequest{
		Messages: []TextGenerationMessage{
			{
				Role:    "system",
				Content: temporaryAIMessageSystemPrompt,
			},
			{
				Role:    "user",
				Content: message,
			},
		},
	}
}

// BuildAssetFingerprintExtractionRequest asks the model to normalize messy product text.
func (textGenerationServiceImpl) BuildAssetFingerprintExtractionRequest(rawText string, deterministicFingerprint string, assetName string, assetType string, assetOperatingSystem string) TextGenerationRequest {
	return BuildAssetFingerprintExtractionRequest(rawText, deterministicFingerprint, assetName, assetType, assetOperatingSystem)
}

// BuildAssetFingerprintExtractionRequest asks the model to normalize messy product text.
func BuildAssetFingerprintExtractionRequest(rawText string, deterministicFingerprint string, assetName string, assetType string, assetOperatingSystem string) TextGenerationRequest {
	payload := struct {
		RawText                  string `json:"rawText"`
		DeterministicFingerprint string `json:"deterministicFingerprint"`
		AssetName                string `json:"assetName"`
		AssetType                string `json:"assetType"`
		AssetOperatingSystem     string `json:"assetOperatingSystem"`
	}{
		RawText:                  rawText,
		DeterministicFingerprint: deterministicFingerprint,
		AssetName:                assetName,
		AssetType:                assetType,
		AssetOperatingSystem:     assetOperatingSystem,
	}

	return buildPromptRequest(assetFingerprintExtractionSystemPrompt, payload)
}

// BuildAssetMatchRankingRequest constructs the locked prompt envelope used for asset matching.
func (textGenerationServiceImpl) BuildAssetMatchRankingRequest(fingerprint string, keywordSearch string, candidates []cpeclient.CPECandidate) TextGenerationRequest {
	return BuildAssetMatchRankingRequest(fingerprint, keywordSearch, candidates)
}

// BuildAssetMatchRankingRequest constructs the locked prompt envelope used for asset matching.
func BuildAssetMatchRankingRequest(fingerprint string, keywordSearch string, candidates []cpeclient.CPECandidate) TextGenerationRequest {
	limitedCandidates := limitAssetMatchCandidates(candidates)
	payload := struct {
		Fingerprint   string                   `json:"fingerprint"`
		KeywordSearch string                   `json:"keywordSearch"`
		Candidates    []cpeclient.CPECandidate `json:"candidates"`
	}{
		Fingerprint:   fingerprint,
		KeywordSearch: keywordSearch,
		Candidates:    limitedCandidates,
	}

	return buildPromptRequest(assetMatchSystemPrompt, payload)
}

// BuildAssetCVERankingRequest constructs the locked prompt envelope used for NVD CVE keyword fallback ranking.
func (textGenerationServiceImpl) BuildAssetCVERankingRequest(fingerprint string, keywordSearches []string, candidates []cveclient.CVELookupResponse) TextGenerationRequest {
	return BuildAssetCVERankingRequest(fingerprint, keywordSearches, candidates)
}

// BuildAssetCVERankingRequest constructs the locked prompt envelope used for NVD CVE keyword fallback ranking.
func BuildAssetCVERankingRequest(fingerprint string, keywordSearches []string, candidates []cveclient.CVELookupResponse) TextGenerationRequest {
	limitedCandidates := limitAssetCVECandidates(candidates)
	payload := struct {
		Fingerprint     string                        `json:"fingerprint"`
		KeywordSearches []string                      `json:"keywordSearches"`
		Candidates      []cveclient.CVELookupResponse `json:"candidates"`
	}{
		Fingerprint:     fingerprint,
		KeywordSearches: keywordSearches,
		Candidates:      limitedCandidates,
	}

	return buildPromptRequest(assetCVERankingSystemPrompt, payload)
}

// BuildAssetCVEKeywordSearchRequest asks the model for bounded NVD keyword search phrases.
func (textGenerationServiceImpl) BuildAssetCVEKeywordSearchRequest(fingerprint string, deterministicSearches []string) TextGenerationRequest {
	return BuildAssetCVEKeywordSearchRequest(fingerprint, deterministicSearches)
}

// BuildAssetCVEKeywordSearchRequest asks the model for bounded NVD keyword search phrases.
func BuildAssetCVEKeywordSearchRequest(fingerprint string, deterministicSearches []string) TextGenerationRequest {
	payload := struct {
		Fingerprint            string   `json:"fingerprint"`
		DeterministicSearches  []string `json:"deterministicSearches"`
		MaxKeywordSearches     int      `json:"maxKeywordSearches"`
		MaxWordsPerKeyword     int      `json:"maxWordsPerKeyword"`
		UseOnlyForNVDCandidate bool     `json:"useOnlyForNvdCandidateSearch"`
	}{
		Fingerprint:            fingerprint,
		DeterministicSearches:  deterministicSearches,
		MaxKeywordSearches:     5,
		MaxWordsPerKeyword:     6,
		UseOnlyForNVDCandidate: true,
	}

	return buildPromptRequest(assetCVEKeywordSearchSystemPrompt, payload)
}
