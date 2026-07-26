/*
Package text_generation interface defines the text-generation request builder
contract used by services and controllers that create backend-owned AI prompts.
*/
package text_generation

import (
	cpeclient "blackradar/api/external/nvd_cpe"
	cveclient "blackradar/api/external/nvd_cve"
)

type TextGenerationService interface {
	/*
		BuildDiagnosticRequest constructs the fixed provider-connectivity prompt.

		Implementations should return a locked request that asks the provider for
		a deterministic health-check response and must not include user-controlled
		system instructions or sensitive runtime data.
	*/
	BuildDiagnosticRequest() TextGenerationRequest

	/*
		BuildTemporaryMessageRequest constructs the admin-only temporary message
		prompt.

		Implementations should wrap the supplied message with the locked
		diagnostic system prompt so user content is treated as input, not as
		provider-level instructions.
	*/
	BuildTemporaryMessageRequest(message string) TextGenerationRequest

	/*
		BuildAssetFingerprintExtractionRequest constructs the prompt used to
		normalize messy asset identity text.

		Implementations should include deterministic fingerprint data and asset
		display fields as bounded payload data, while preserving prompt-injection
		guardrails that prevent the provider from inventing CVEs or external
		facts.
	*/
	BuildAssetFingerprintExtractionRequest(rawText string, deterministicFingerprint string, assetName string, assetType string, assetOperatingSystem string) TextGenerationRequest

	/*
		BuildAssetCreationExtractionRequest constructs the prompt used to turn
		messy user-provided text into an asset draft.

		Implementations should keep raw text inside a JSON payload, enforce the
		locked asset extraction schema, and avoid including tenant, credential, or
		backend runtime data.
	*/
	BuildAssetCreationExtractionRequest(rawText string) TextGenerationRequest

	/*
		BuildAssetMatchRankingRequest constructs the prompt used to rank NVD CPE
		candidates for one asset fingerprint.

		Implementations should bound the candidate list before building the
		request, include only the provided NVD CPE candidates, and preserve the
		locked JSON-only ranking contract.
	*/
	BuildAssetMatchRankingRequest(fingerprint string, keywordSearch string, candidates []cpeclient.CPECandidate) TextGenerationRequest

	/*
		BuildAssetCVERankingRequest constructs the prompt used to rank NVD CVE
		candidates for keyword fallback matching.

		Implementations should bound the CVE candidate list, treat fingerprint
		and keyword values as untrusted input data, and preserve the locked
		JSON-only CVE selection contract.
	*/
	BuildAssetCVERankingRequest(fingerprint string, keywordSearches []string, candidates []cveclient.CVELookupResponse) TextGenerationRequest

	/*
		BuildAssetCVEKeywordSearchRequest constructs the prompt used to generate
		bounded NVD keyword search phrases.

		Implementations should include deterministic searches as input data,
		limit generated phrase expectations through the prompt contract, and
		prevent the provider from returning CVE claims or arbitrary prose.
	*/
	BuildAssetCVEKeywordSearchRequest(fingerprint string, deterministicSearches []string) TextGenerationRequest
}
