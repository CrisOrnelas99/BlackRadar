// Package asset_match support contains normalization, ranking, and matching helpers.
package asset_match

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	nvdcpeclient "blackradar/api/external/nvd_cpe"
	nvdcveclient "blackradar/api/external/nvd_cve"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
	assetmatchrepo "blackradar/api/repository/asset_match"
	assetvulnerabilityrepo "blackradar/api/repository/asset_vulnerability"
	vulnerabilityrepo "blackradar/api/repository/vulnerability"
	assetservice "blackradar/api/service/asset"
	assetvulnerabilityservice "blackradar/api/service/asset_vulnerability"
	textgenerationservice "blackradar/api/service/text_generation"
)

// fingerprintHints stores product identity extracted from free-form asset text.
type fingerprintHints struct {
	vendor          string
	product         string
	version         string
	operatingSystem string
	deviceModel     string
}

var (
	versionHintPattern     = regexp.MustCompile(`(?i)\b(?:version|release)\s+(?:is\s+)?([a-z0-9][a-z0-9._-]*)`)
	packageFromVendor      = regexp.MustCompile(`(?i)\b(?:package|product|software|application|app)\s+(?:is\s+|called\s+|named\s+)([a-z0-9][a-z0-9._+-]*)\s+(?:installed\s+)?(?:from|by)\s+(?:the\s+)?([a-z0-9][a-z0-9 ._-]*?)(?:\s+(?:project|vendor|team|foundation|software foundation))?\b`)
	namedPackageFromVendor = regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9._+-]*)\s+(?:package|software|application|app)\s+(?:installed\s+)?(?:from|by)\s+(?:the\s+)?([a-z0-9][a-z0-9 ._-]*?)(?:\s+(?:project|vendor|team|foundation|software foundation))?\b`)
	apacheHTTPServerHint   = regexp.MustCompile(`(?i)\bapache\s+http\s+server\b`)
	matchCVEIDPattern      = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	promptInjectionPattern = regexp.MustCompile(`(?i)(ignore (all )?previous instructions|system prompt|developer message|reveal the prompt|bypass policy|prompt injection|jailbreak|do anything now)`)
)

const (
	aiIngestionMaxBytes = 8192
	aiIngestionMaxRunes = 4000
)

// textGenerationBuilder returns the configured text-generation builder or the default one.
func (s *assetMatchServiceImpl) textGenerationBuilder() textgenerationservice.TextGenerationService {
	if s.textGeneration != nil {
		return s.textGeneration
	}
	return textgenerationservice.NewTextGenerationService()
}

// BuildAssetFingerprint turns an asset and optional pasted text into a normalized fingerprint.
func BuildAssetFingerprint(asset model.Asset, rawText string) AssetFingerprint {
	hints := extractFingerprintHints(rawText)

	fingerprint := AssetFingerprint{
		Vendor:          firstNonEmpty(normalizeFingerprintValue(hints.vendor), normalizeOptionalFingerprintValue(asset.Vendor)),
		Product:         firstNonEmpty(normalizeFingerprintValue(hints.product), normalizeOptionalFingerprintValue(asset.Product)),
		Version:         firstNonEmpty(normalizeFingerprintValue(hints.version), normalizeOptionalFingerprintValue(asset.Version)),
		OperatingSystem: firstNonEmpty(normalizeFingerprintValue(hints.operatingSystem), normalizeOptionalFingerprintValue(asset.OperatingSystem)),
		DeviceModel:     firstNonEmpty(normalizeFingerprintValue(hints.deviceModel), normalizeOptionalFingerprintValue(asset.DeviceModel)),
		AssetName:       normalizeFingerprintValue(asset.Name),
		AssetType:       normalizeFingerprintValue(asset.Type),
	}

	if fingerprint.DeviceModel == "" {
		fingerprint.DeviceModel = extractModelHint(fingerprint.AssetName)
	}

	fingerprint.Canonical = composeAssetFingerprint(fingerprint)
	return fingerprint
}

// extractFingerprintHints parses explicit and sentence-style product hints from raw text.
func extractFingerprintHints(rawText string) fingerprintHints {
	hints := fingerprintHints{}
	for _, segment := range fingerprintTextSegments(rawText) {
		normalizedLine := normalizeFingerprintLine(segment)
		if normalizedLine == "" {
			continue
		}

		if value, ok := extractLabeledValue(normalizedLine, "vendor", "manufacturer", "maker"); ok {
			hints.vendor = value
		}
		if value, ok := extractLabeledValue(normalizedLine, "product", "software", "application", "app"); ok {
			hints.product = value
		}
		if value, ok := extractLabeledValue(normalizedLine, "version", "release"); ok {
			hints.version = value
		}
		if value, ok := extractLabeledValue(normalizedLine, "operating system", "os", "platform"); ok {
			hints.operatingSystem = value
		}
		if value, ok := extractLabeledValue(normalizedLine, "model", "device model", "hardware model"); ok {
			hints.deviceModel = value
		}
	}

	applySentenceFingerprintHints(&hints, rawText)
	return hints
}

// fingerprintTextSegments splits free-form text into label-friendly segments.
func fingerprintTextSegments(rawText string) []string {
	replacer := strings.NewReplacer(
		"\r\n", "\n",
		"\r", "\n",
		",", "\n",
		";", "\n",
	)
	rawText = replacer.Replace(rawText)
	return strings.Split(rawText, "\n")
}

// extractLabeledValue returns a normalized value after one of the supplied labels.
func extractLabeledValue(line string, labels ...string) (string, bool) {
	lowerLine := strings.ToLower(strings.TrimSpace(line))
	for _, label := range labels {
		lowerLabel := strings.ToLower(label)
		for _, prefix := range []string{lowerLabel, "the " + lowerLabel} {
			if lowerLine == prefix {
				continue
			}
			if !strings.HasPrefix(lowerLine, prefix) {
				continue
			}

			remainder := strings.TrimSpace(line[len(prefix):])
			remainder = strings.TrimLeft(remainder, ":=- \t")
			remainder = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(remainder), "is "))
			remainder = normalizeFingerprintValue(remainder)
			if remainder == "" {
				continue
			}

			return remainder, true
		}
	}

	return "", false
}

// applySentenceFingerprintHints extracts product hints from sentence-style text.
func applySentenceFingerprintHints(hints *fingerprintHints, rawText string) {
	normalizedText := normalizeFingerprintLine(rawText)
	if normalizedText == "" {
		return
	}

	if hints.version == "" {
		hints.version = firstRegexGroup(versionHintPattern, normalizedText, 1)
	}
	if hints.product == "" || hints.vendor == "" {
		applyPackageVendorHint(hints, normalizedText)
	}
	if hints.product == "" || hints.vendor == "" {
		applyKnownProductHint(hints, normalizedText)
	}
}

// applyPackageVendorHint extracts package and vendor names from known sentence patterns.
func applyPackageVendorHint(hints *fingerprintHints, normalizedText string) {
	for _, pattern := range []*regexp.Regexp{packageFromVendor, namedPackageFromVendor} {
		matches := pattern.FindStringSubmatch(normalizedText)
		if len(matches) < 3 {
			continue
		}

		product := normalizeFingerprintValue(matches[1])
		vendor := normalizeVendorHint(matches[2])
		if product == "" || vendor == "" {
			continue
		}
		if hints.product == "" {
			hints.product = product
		}
		if hints.vendor == "" {
			hints.vendor = vendor
		}
		return
	}
}

// applyKnownProductHint handles product names that need deterministic normalization.
func applyKnownProductHint(hints *fingerprintHints, normalizedText string) {
	if apacheHTTPServerHint.MatchString(normalizedText) {
		if hints.vendor == "" {
			hints.vendor = "apache"
		}
		if hints.product == "" {
			hints.product = "http server"
		}
	}
}

// firstRegexGroup returns the normalized capture group for a regex match.
func firstRegexGroup(pattern *regexp.Regexp, value string, groupIndex int) string {
	matches := pattern.FindStringSubmatch(value)
	if len(matches) <= groupIndex {
		return ""
	}
	return normalizeFingerprintValue(matches[groupIndex])
}

// normalizeVendorHint removes generic vendor suffixes from a normalized hint.
func normalizeVendorHint(value string) string {
	value = normalizeFingerprintValue(value)
	for _, suffix := range []string{" software foundation", " project", " vendor", " team", " foundation"} {
		if strings.HasSuffix(value, suffix) {
			value = strings.TrimSpace(strings.TrimSuffix(value, suffix))
		}
	}
	return value
}

// normalizeFingerprintLine normalizes whitespace in a fingerprint text line.
func normalizeFingerprintLine(value string) string {
	value = strings.ReplaceAll(value, "\t", " ")
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	fields := strings.Fields(value)
	return strings.Join(fields, " ")
}

// normalizeFingerprintValue normalizes one fingerprint value for matching.
func normalizeFingerprintValue(value string) string {
	value = normalizeFingerprintLine(value)
	if value == "" {
		return ""
	}

	value = strings.Trim(value, `"'`+"`")
	value = strings.Trim(value, ".,;")
	return strings.ToLower(strings.TrimSpace(value))
}

// normalizeOptionalFingerprintValue normalizes an optional fingerprint value.
func normalizeOptionalFingerprintValue(value *string) string {
	if value == nil {
		return ""
	}
	return normalizeFingerprintValue(*value)
}

// firstNonEmpty returns the first non-empty normalized value.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// extractModelHint returns the last asset-name token as a weak model hint.
func extractModelHint(value string) string {
	if value == "" {
		return ""
	}

	fields := strings.Fields(value)
	if len(fields) < 2 {
		return ""
	}

	return fields[len(fields)-1]
}

// composeAssetFingerprint builds the canonical fingerprint string.
func composeAssetFingerprint(fingerprint AssetFingerprint) string {
	parts := make([]string, 0, 7)
	appendPart := func(name string, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		parts = append(parts, name+"="+value)
	}

	appendPart("vendor", fingerprint.Vendor)
	appendPart("product", fingerprint.Product)
	appendPart("version", fingerprint.Version)
	appendPart("operating_system", fingerprint.OperatingSystem)
	appendPart("device_model", fingerprint.DeviceModel)
	appendPart("asset_name", fingerprint.AssetName)
	appendPart("asset_type", fingerprint.AssetType)

	return strings.Join(parts, ";")
}

// translateMatchRepositoryError maps repository errors to asset match service errors.
func translateMatchRepositoryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, assetmatchrepo.ErrRecordNotFound):
		return fmt.Errorf("%w: %w", assetservice.ErrAssetNotFound, err)
	case errors.Is(err, vulnerabilityrepo.ErrRecordNotFound):
		return fmt.Errorf("%w: %w", assetvulnerabilityservice.ErrAssetVulnerabilityNotFound, err)
	case errors.Is(err, assetvulnerabilityrepo.ErrRecordNotFound):
		return fmt.Errorf("%w: %w", assetvulnerabilityservice.ErrAssetVulnerabilityNotFound, err)
	case errors.Is(err, assetvulnerabilityrepo.ErrDuplicateRelationship):
		return fmt.Errorf("%w: %w", assetvulnerabilityservice.ErrDuplicateAssetVulnerability, err)
	case errors.Is(err, assetmatchrepo.ErrNotNullViolation),
		errors.Is(err, assetmatchrepo.ErrForeignKeyViolation),
		errors.Is(err, assetvulnerabilityrepo.ErrNotNullViolation),
		errors.Is(err, assetvulnerabilityrepo.ErrForeignKeyViolation),
		errors.Is(err, vulnerabilityrepo.ErrNotNullViolation),
		errors.Is(err, vulnerabilityrepo.ErrForeignKeyViolation):
		return fmt.Errorf("%w: %w", assetservice.ErrInvalidAssetData, err)
	default:
		return fmt.Errorf("%w: %w", ErrMatchDependency, err)
	}
}

// assetMatchRankingResponse represents the constrained AI CPE ranking response.
type assetMatchRankingResponse struct {
	SelectedCPE string   `json:"selectedCpe"`
	Confidence  float64  `json:"confidence"`
	ReviewNotes string   `json:"reviewNotes"`
	RankedCPEs  []string `json:"rankedCpes"`
}

// assetCVERankingResponse represents the constrained AI CVE ranking response.
type assetCVERankingResponse struct {
	SelectedCVEIDs []string `json:"selectedCveIds"`
	Confidence     float64  `json:"confidence"`
	ReviewNotes    string   `json:"reviewNotes"`
}

// assetCVEKeywordSearchResponse represents AI-generated CVE keyword searches.
type assetCVEKeywordSearchResponse struct {
	KeywordSearches []string `json:"keywordSearches"`
	ReviewNotes     string   `json:"reviewNotes"`
}

// cveMatchResult stores CVE candidates and the search source that produced them.
type cveMatchResult struct {
	CVEs            []nvdcveclient.CVELookupResponse
	CPEName         string
	KeywordSearches []string
	Confidence      float64
	ReviewNotes     string
	KeywordFallback bool
}

// assetFingerprintExtractionResponse represents the constrained AI fingerprint response.
type assetFingerprintExtractionResponse struct {
	Vendor          any `json:"vendor"`
	Product         any `json:"product"`
	Version         any `json:"version"`
	OperatingSystem any `json:"operatingSystem"`
	DeviceModel     any `json:"deviceModel"`
	Confidence      any `json:"confidence"`
	ReviewNotes     any `json:"reviewNotes"`
}

// normalizeFingerprintWithAI asks AI to normalize messy fingerprint text when deterministic parsing is weak.
func fingerprintExtractionRawText(extraction assetFingerprintExtractionResponse, fallback AssetFingerprint) string {
	values := []string{
		"Vendor: " + firstNonEmptyString(jsonStringValue(extraction.Vendor), fallback.Vendor),
		"Product: " + firstNonEmptyString(jsonStringValue(extraction.Product), fallback.Product),
		"Version: " + firstNonEmptyString(jsonStringValue(extraction.Version), fallback.Version),
		"Operating System: " + firstNonEmptyString(jsonStringValue(extraction.OperatingSystem), fallback.OperatingSystem),
		"Model: " + firstNonEmptyString(jsonStringValue(extraction.DeviceModel), fallback.DeviceModel),
	}

	lines := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(strings.TrimSuffix(value, ": ")) != "" && !strings.HasSuffix(value, ": ") {
			lines = append(lines, value)
		}
	}
	return strings.Join(lines, "\n")
}

// jsonStringValue converts a decoded JSON scalar into a trimmed string.
func jsonStringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		return strings.TrimSpace(fmt.Sprintf("%v", typed))
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", typed))
	}
}

// extractionConfidence converts AI confidence values into a numeric score.
func extractionConfidence(value any) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "high", "strong":
			return 0.9
		case "medium", "moderate":
			return 0.65
		case "low", "weak":
			return 0.3
		default:
			return 0
		}
	default:
		return 0
	}
}

// firstNonEmptyString returns the first non-empty trimmed string.
func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// optionalStringValue returns a trimmed value for optional strings.
func optionalStringValue(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

// fallbackCPENames builds deterministic CPE names from a strong canonical fingerprint.
func fallbackCPENames(canonicalFingerprint string) []string {
	fields := parseCanonicalFingerprint(canonicalFingerprint)
	vendor := fields["vendor"]
	product := fields["product"]
	version := fields["version"]
	if vendor == "" || product == "" || version == "" {
		return nil
	}

	candidates := make([]string, 0, 24)
	for _, vendorAlias := range cpeComponentAliases(vendor) {
		for _, productAlias := range cpeProductAliases(product, fields["operating_system"]) {
			for _, part := range []string{"a", "o", "h"} {
				cpeName := "cpe:2.3:" + part + ":" + vendorAlias + ":" + productAlias + ":" + cpeComponent(version) + ":*:*:*:*:*:*:*"
				if !containsString(candidates, cpeName) {
					candidates = append(candidates, cpeName)
				}
			}
		}
	}

	return candidates
}

// parseCanonicalFingerprint parses canonical fingerprint fields into a map.
func parseCanonicalFingerprint(canonicalFingerprint string) map[string]string {
	fields := make(map[string]string)
	for _, part := range strings.Split(canonicalFingerprint, ";") {
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		fields[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}
	return fields
}

// cpeComponentAliases returns CPE-safe aliases for one vendor or product component.
func cpeComponentAliases(value string) []string {
	normalized := cpeComponent(value)
	aliases := []string{normalized}
	for _, suffix := range []string{"_software_foundation", "_software", "_utils", "_project"} {
		if strings.HasSuffix(normalized, suffix) {
			alias := strings.TrimSuffix(normalized, suffix)
			if alias != "" && !containsString(aliases, alias) {
				aliases = append(aliases, alias)
			}
		}
	}
	if normalized == "xz_utils" && !containsString(aliases, "xz") {
		aliases = append(aliases, "xz")
	}
	return aliases
}

// cpeComponent normalizes one value for use as a CPE component.
func cpeComponent(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.NewReplacer(" ", "_", "-", "_").Replace(value)
	return strings.Trim(value, "_")
}

// containsString reports whether values contains target.
func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// searchCPECandidates tries CPE keyword searches until NVD returns candidates.
func buildCPEKeywordSearches(fingerprint AssetFingerprint) []string {
	searches := make([]string, 0, 5)
	appendSearch := func(parts ...string) {
		values := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				values = append(values, part)
			}
		}
		search := strings.Join(values, " ")
		if search == "" {
			return
		}
		for _, existing := range searches {
			if existing == search {
				return
			}
		}
		searches = append(searches, search)
	}

	for _, vendor := range keywordAliases(fingerprint.Vendor) {
		for _, product := range keywordProductAliases(fingerprint.Product, fingerprint.OperatingSystem) {
			appendSearch(vendor, product)
			appendSearch(vendor, product, fingerprint.Version)
			appendSearch(product, fingerprint.Version)
			appendSearch(vendor, product, fingerprint.OperatingSystem)
			appendSearch(product)
		}
	}

	return searches
}

// buildCVEKeywordSearches creates bounded NVD CVE fallback search terms.
func buildCVEKeywordSearches(canonicalFingerprint string) []string {
	fields := parseCanonicalFingerprint(canonicalFingerprint)
	product := fields["product"]
	version := fields["version"]
	assetName := fields["asset_name"]
	deviceModel := fields["device_model"]
	operatingSystem := fields["operating_system"]
	nameFallback := strings.TrimSpace(product) == ""

	searches := make([]string, 0, maxKeywordFallbackSearches)
	appendSearch := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || containsString(searches, value) || len(searches) >= maxKeywordFallbackSearches {
			return
		}
		searches = append(searches, value)
	}

	appendSearch(trimGenericProductSuffixPreservingSeparators(product))
	normalizedProduct := normalizedSearchPhrase(product)
	withoutGenericSuffix := trimGenericProductSuffix(normalizedProduct)
	if withoutGenericSuffix != "" {
		appendSearch(withoutGenericSuffix)
	}
	appendSearch(normalizedProduct)
	for _, variant := range productContextKeywordVariants(normalizedProduct, assetName, deviceModel, operatingSystem, fields["asset_type"]) {
		appendSearch(variant)
	}
	appendNGrams := func(value string, size int) {
		for _, phrase := range nGramSearches(value, size) {
			appendSearch(phrase)
		}
	}
	appendNGrams(product, 3)
	if nameFallback {
		appendNGrams(assetName, 3)
	}
	if version != "" && withoutGenericSuffix != "" {
		appendSearch(withoutGenericSuffix + " " + version)
	}
	if strings.Contains(normalizedSearchPhrase(product+" "+assetName+" "+deviceModel+" "+operatingSystem), "wordpress") ||
		strings.Contains(normalizedSearchPhrase(product+" "+assetName+" "+deviceModel), "plugin") {
		appendSearch("wordpress plugin")
	}
	appendNGrams(product, 2)
	if nameFallback {
		appendNGrams(assetName, 2)
	}

	return searches
}

// mergeCVEKeywordSearches merges AI and deterministic keyword searches with bounds.
func mergeCVEKeywordSearches(primary []string, fallback []string) []string {
	searches := make([]string, 0, maxKeywordFallbackSearches)
	appendSearch := func(value string) {
		value = normalizeAIKeywordSearch(value)
		if value == "" || containsString(searches, value) || len(searches) >= maxKeywordFallbackSearches {
			return
		}
		searches = append(searches, value)
	}

	for index, value := range fallback {
		if index >= 3 {
			break
		}
		appendSearch(value)
	}
	for _, value := range primary {
		appendSearch(value)
	}
	for _, value := range fallback {
		appendSearch(value)
	}

	return searches
}

// productContextKeywordVariants adds product search suffixes based on asset context.
func productContextKeywordVariants(product string, assetName string, deviceModel string, operatingSystem string, assetType string) []string {
	product = normalizedSearchPhrase(product)
	if product == "" {
		return nil
	}

	context := normalizedSearchPhrase(product + " " + assetName + " " + deviceModel + " " + operatingSystem + " " + assetType)
	variants := make([]string, 0, 4)
	appendVariant := func(suffix string) {
		variant := strings.TrimSpace(product + " " + suffix)
		if variant != "" && !containsString(variants, variant) {
			variants = append(variants, variant)
		}
	}

	if strings.Contains(context, "network") || strings.Contains(context, "controller") {
		appendVariant("application")
		appendVariant("controller")
	}
	if strings.Contains(context, "device") || strings.Contains(context, "firmware") {
		appendVariant("firmware")
	}
	if strings.Contains(context, "plugin") {
		appendVariant("plugin")
	}
	if strings.Contains(context, "library") || strings.Contains(context, "wrapper") {
		appendVariant("library")
		appendVariant("wrapper")
	}

	return variants
}

// normalizeAIKeywordSearch validates and normalizes an AI-generated keyword search.
func normalizeAIKeywordSearch(value string) string {
	value = normalizedSearchPhrase(value)
	if value == "" || len(value) > 120 {
		return ""
	}

	words := strings.Fields(value)
	if len(words) < 2 || len(words) > 6 {
		return ""
	}
	for _, word := range words {
		if len(word) > 40 {
			return ""
		}
	}

	for _, broad := range []string{"aws", "windows", "linux", "wordpress", "network device"} {
		if value == broad {
			return ""
		}
	}

	return value
}

// keywordAliases returns keyword-search aliases for vendor or product text.
func keywordAliases(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return []string{""}
	}

	aliases := []string{value}
	for _, suffix := range []string{" software foundation", " software", " utils", " project"} {
		if strings.HasSuffix(value, suffix) {
			alias := strings.TrimSpace(strings.TrimSuffix(value, suffix))
			if alias != "" && !containsString(aliases, alias) {
				aliases = append(aliases, alias)
			}
		}
	}
	if value == "xz utils" && !containsString(aliases, "xz") {
		aliases = append(aliases, "xz")
	}
	return aliases
}

// filterRelevantKeywordCVEs keeps keyword CVEs that mention product aliases.
func filterRelevantKeywordCVEs(cves []nvdcveclient.CVELookupResponse, canonicalFingerprint string) []nvdcveclient.CVELookupResponse {
	aliases := productRelevanceAliases(canonicalFingerprint)
	if len(aliases) == 0 {
		return nil
	}

	filtered := make([]nvdcveclient.CVELookupResponse, 0, len(cves))
	for _, cve := range cves {
		text := normalizedSearchPhrase(cve.Title + " " + cve.Description)
		for _, alias := range aliases {
			if alias != "" && strings.Contains(text, alias) {
				filtered = append(filtered, cve)
				break
			}
		}
	}
	return filtered
}

// productRelevanceAliases builds product phrases used to filter broad CVE results.
func productRelevanceAliases(canonicalFingerprint string) []string {
	fields := parseCanonicalFingerprint(canonicalFingerprint)
	values := []string{fields["product"]}
	if strings.TrimSpace(fields["product"]) == "" {
		values = append(values, fields["asset_name"])
	}
	values = append(values, fields["device_model"])

	aliases := make([]string, 0, 8)
	appendAlias := func(value string) {
		value = normalizedSearchPhrase(value)
		if value == "" || containsString(aliases, value) {
			return
		}
		if len(strings.Fields(value)) < 2 {
			return
		}
		aliases = append(aliases, value)
	}

	for _, value := range values {
		appendAlias(value)
		appendAlias(trimGenericProductSuffix(value))
		for _, phrase := range nGramSearches(value, 3) {
			appendAlias(phrase)
		}
	}
	return aliases
}

// selectRankedCVEs returns candidate CVEs selected by the AI ranking response.
func selectRankedCVEs(candidates []nvdcveclient.CVELookupResponse, selectedCVEIDs []string) []nvdcveclient.CVELookupResponse {
	byID := make(map[string]nvdcveclient.CVELookupResponse, len(candidates))
	for _, cve := range candidates {
		cveID := normalizeCVEID(cve.CVEID)
		if cveID != "" {
			byID[cveID] = cve
		}
	}

	selected := make([]nvdcveclient.CVELookupResponse, 0, min(len(selectedCVEIDs), maxAutoAttachedCVEs))
	for _, cveID := range selectedCVEIDs {
		cve, ok := byID[normalizeCVEID(cveID)]
		if !ok {
			continue
		}
		if containsCVEID(selected, cve.CVEID) {
			continue
		}
		selected = append(selected, cve)
		if len(selected) >= maxAutoAttachedCVEs {
			break
		}
	}
	return selected
}

// sortCVECandidatesByPublishedAtDesc orders CVE candidates by newest published date first.
func sortCVECandidatesByPublishedAtDesc(candidates []nvdcveclient.CVELookupResponse) {
	sort.SliceStable(candidates, func(i, j int) bool {
		left := strings.TrimSpace(candidates[i].PublishedAt)
		right := strings.TrimSpace(candidates[j].PublishedAt)
		if left == "" {
			return false
		}
		if right == "" {
			return true
		}
		return left > right
	})
}

// containsCVEID reports whether a CVE list contains the normalized CVE ID.
func containsCVEID(cves []nvdcveclient.CVELookupResponse, cveID string) bool {
	cveID = normalizeCVEID(cveID)
	for _, cve := range cves {
		if normalizeCVEID(cve.CVEID) == cveID {
			return true
		}
	}
	return false
}

// cveIDs returns unique normalized CVE IDs from lookup responses.
func cveIDs(cves []nvdcveclient.CVELookupResponse) []string {
	ids := make([]string, 0, len(cves))
	for _, cve := range cves {
		cveID := normalizeCVEID(cve.CVEID)
		if cveID != "" && !containsString(ids, cveID) {
			ids = append(ids, cveID)
		}
	}
	return ids
}

// logAssetMatchDebug logs asset-match diagnostics with a safe fallback logger.
func logAssetMatchDebug(logger *slog.Logger, message string, args ...any) {
	if logger == nil {
		logger = slog.Default()
	}
	logger.Info(message, args...)
}

// nGramSearches returns normalized word n-grams for keyword fallback.
func nGramSearches(value string, size int) []string {
	words := strings.Fields(normalizedSearchPhrase(value))
	if size <= 0 || len(words) < size {
		return nil
	}

	searches := make([]string, 0, len(words)-size+1)
	for index := 0; index <= len(words)-size; index++ {
		searches = append(searches, strings.Join(words[index:index+size], " "))
	}
	return searches
}

// trimGenericProductSuffix removes generic product suffix words from normalized text.
func trimGenericProductSuffix(value string) string {
	words := strings.Fields(normalizedSearchPhrase(value))
	for len(words) > 2 {
		last := words[len(words)-1]
		switch last {
		case "plugin", "plugins", "software", "firmware", "application", "app", "controller":
			words = words[:len(words)-1]
		default:
			return strings.Join(words, " ")
		}
	}
	return strings.Join(words, " ")
}

// trimGenericProductSuffixPreservingSeparators trims generic suffixes without re-tokenizing.
func trimGenericProductSuffixPreservingSeparators(value string) string {
	value = strings.TrimSpace(value)
	for _, suffix := range []string{" plugin", " plugins", " software", " firmware", " application", " app"} {
		if strings.HasSuffix(strings.ToLower(value), suffix) && len(strings.Fields(normalizedSearchPhrase(value))) > 2 {
			return strings.TrimSpace(value[:len(value)-len(suffix)])
		}
	}
	return value
}

// normalizedSearchPhrase returns lowercase alphanumeric words joined by spaces.
func normalizedSearchPhrase(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		default:
			return ' '
		}
	}, value)
	return strings.Join(strings.Fields(value), " ")
}

// keywordProductAliases returns keyword aliases for product and firmware context.
func keywordProductAliases(product string, operatingSystem string) []string {
	aliases := keywordAliases(product)
	if shouldTryFirmwareAlias(product, operatingSystem) {
		firmwareProduct := strings.TrimSpace(product + " firmware")
		if firmwareProduct != "" && !containsString(aliases, firmwareProduct) {
			aliases = append(aliases, firmwareProduct)
		}
		normalizedOS := strings.TrimSpace(operatingSystem)
		if normalizedOS != "" && !containsString(aliases, normalizedOS) {
			aliases = append(aliases, normalizedOS)
		}
	}
	return aliases
}

// cpeProductAliases returns CPE component aliases for product and firmware context.
func cpeProductAliases(product string, operatingSystem string) []string {
	aliases := cpeComponentAliases(product)
	if shouldTryFirmwareAlias(product, operatingSystem) {
		for _, alias := range cpeComponentAliases(product + " firmware") {
			if alias != "" && !containsString(aliases, alias) {
				aliases = append(aliases, alias)
			}
		}
		for _, alias := range cpeComponentAliases(operatingSystem) {
			if alias != "" && !containsString(aliases, alias) {
				aliases = append(aliases, alias)
			}
		}
	}
	return aliases
}

// shouldTryFirmwareAlias reports whether firmware aliases should be searched.
func shouldTryFirmwareAlias(product string, operatingSystem string) bool {
	product = strings.ToLower(strings.TrimSpace(product))
	operatingSystem = strings.ToLower(strings.TrimSpace(operatingSystem))
	return product != "" && strings.Contains(operatingSystem, "firmware") && !strings.Contains(product, "firmware")
}

// isStrongFingerprint reports whether a fingerprint has enough product identity.
func isStrongFingerprint(fingerprint AssetFingerprint) bool {
	return strings.TrimSpace(fingerprint.Vendor) != "" && strings.TrimSpace(fingerprint.Product) != ""
}

// containsCPECandidate reports whether CPE candidates include the selected CPE.
func containsCPECandidate(candidates []nvdcpeclient.CPECandidate, cpeName string) bool {
	for _, candidate := range candidates {
		if normalizeCPEName(candidate.CPEName) == normalizeCPEName(cpeName) {
			return true
		}
	}
	return false
}

// normalizeCPEName normalizes a CPE name for equality checks.
func normalizeCPEName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// decodeRankingResponse decodes an AI JSON response after stripping markdown fences.
func decodeRankingResponse(raw string, target any) error {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.TrimPrefix(trimmed, "```json")
	trimmed = strings.TrimPrefix(trimmed, "```")
	trimmed = strings.TrimSuffix(trimmed, "```")
	trimmed = strings.TrimSpace(trimmed)
	if trimmed == "" {
		return fmt.Errorf("%w: empty response", ErrMatchExternalService)
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(trimmed)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: decode ranking response", ErrMatchExternalService)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: decode ranking response", ErrMatchExternalService)
	}
	return nil
}

// stringPtrOrNil returns nil for blank strings and a pointer otherwise.
func stringPtrOrNil(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	trimmed := strings.TrimSpace(value)
	return &trimmed
}

// floatPtrOrNil returns nil for non-positive values and a pointer otherwise.
func floatPtrOrNil(value float64) *float64 {
	if value <= 0 {
		return nil
	}
	copied := value
	return &copied
}

// authenticatedUserID returns the authenticated user ID from request context.
func authenticatedUserID(ec *appcontext.GinContext) (string, error) {
	if ec == nil {
		return "", assetservice.ErrAssetPermissionDenied
	}

	userID, err := ec.UserID()
	if err != nil {
		return "", err
	}

	return userID, nil
}

// authenticatedRole returns the authenticated role from request context.
func authenticatedRole(ec *appcontext.GinContext) (string, error) {
	if ec == nil {
		return "", assetservice.ErrAssetPermissionDenied
	}

	role, err := ec.UserRole()
	if err != nil {
		return "", err
	}

	return role, nil
}

// canManageVulnerabilities reports whether the role can manage vulnerability assignments.
func canManageVulnerabilities(role string) bool {
	return role == model.RoleAdmin
}

// normalizeCVEID trims and uppercases a CVE identifier before lookup.
func normalizeCVEID(cveID string) string {
	return strings.ToUpper(strings.TrimSpace(cveID))
}

// validateCVEID verifies the identifier is safe to use with the NVD CVE API.
func validateCVEID(cveID string) error {
	if !matchCVEIDPattern.MatchString(normalizeCVEID(cveID)) {
		return ErrInvalidCVEID
	}
	return nil
}

// normalizeSeverity converts external severity strings into the app's canonical title-case form.
func normalizeSeverity(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "":
		return ""
	case "low":
		return "Low"
	case "medium":
		return "Medium"
	case "high":
		return "High"
	case "critical":
		return "Critical"
	default:
		return strings.ToUpper(strings.TrimSpace(value))
	}
}

// sanitizeAIIngestionText normalizes pasted asset text and rejects obvious prompt-injection attempts.
func sanitizeAIIngestionText(rawText string) (string, error) {
	if !utf8.ValidString(rawText) {
		return "", ErrInvalidCVEID
	}

	trimmed := strings.TrimSpace(rawText)
	if trimmed == "" {
		return "", ErrInvalidCVEID
	}
	if len(trimmed) > aiIngestionMaxBytes || utf8.RuneCountInString(trimmed) > aiIngestionMaxRunes {
		return "", ErrInvalidCVEID
	}
	if promptInjectionPattern.MatchString(trimmed) {
		return "", ErrInvalidCVEID
	}

	normalized := strings.ReplaceAll(trimmed, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	normalized = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\t':
			return r
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, normalized)

	lines := strings.Split(normalized, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(strings.Join(strings.Fields(line), " "))
	}

	return strings.TrimSpace(strings.Join(lines, "\n")), nil
}
