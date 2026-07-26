package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
	assetrepository "blackradar/api/repository/asset"
)

var aiPromptInjectionPattern = regexp.MustCompile(`(?i)(ignore (all )?previous instructions|system prompt|developer message|reveal the prompt|bypass policy|prompt injection|jailbreak|do anything now)`)

const (
	aiIngestionMaxBytes = 8192
	aiIngestionMaxRunes = 4000
)

var displayAcronyms = map[string]string{
	"api":   "API",
	"aws":   "AWS",
	"cpe":   "CPE",
	"cve":   "CVE",
	"cpu":   "CPU",
	"dns":   "DNS",
	"http":  "HTTP",
	"https": "HTTPS",
	"id":    "ID",
	"iot":   "IoT",
	"ip":    "IP",
	"it":    "IT",
	"nvd":   "NVD",
	"os":    "OS",
	"sql":   "SQL",
	"ssh":   "SSH",
	"tls":   "TLS",
	"ui":    "UI",
	"url":   "URL",
	"vm":    "VM",
}

type assetCreationExtractionResponse struct {
	Name            string  `json:"name"`
	Type            string  `json:"type"`
	OperatingSystem string  `json:"operatingSystem"`
	Vendor          string  `json:"vendor"`
	Product         string  `json:"product"`
	Version         string  `json:"version"`
	DeviceModel     string  `json:"deviceModel"`
	Owner           string  `json:"owner"`
	Criticality     string  `json:"criticality"`
	Confidence      float64 `json:"confidence"`
	ReviewNotes     string  `json:"reviewNotes"`
}

// assetFromAIExtraction converts a validated AI JSON response into an asset model.
func assetFromAIExtraction(raw string) (model.Asset, error) {
	var extraction assetCreationExtractionResponse
	if err := decodeJSONOnly(raw, &extraction); err != nil {
		return model.Asset{}, err
	}

	asset := model.Asset{
		Name:            strings.TrimSpace(extraction.Name),
		Type:            firstNonEmptyString(extraction.Type, "Device"),
		OperatingSystem: stringPtrFromValue(extraction.OperatingSystem),
		Vendor:          stringPtrFromValue(extraction.Vendor),
		Product:         stringPtrFromValue(extraction.Product),
		Version:         stringPtrFromValue(extraction.Version),
		DeviceModel:     stringPtrFromValue(extraction.DeviceModel),
		Owner:           firstNonEmptyString(extraction.Owner, "unassigned"),
		Criticality:     firstNonEmptyString(extraction.Criticality, "Medium"),
		RiskLevel:       nil,
	}
	asset = normalizeAssetDisplayFields(asset)

	if strings.TrimSpace(asset.Name) == "" {
		asset.Name = fallbackAssetName(asset)
	}
	if strings.TrimSpace(asset.Name) == "" {
		return model.Asset{}, ErrInvalidAssetData
	}

	return asset, nil
}

// fallbackAssetName builds a usable asset name from structured product fields.
func fallbackAssetName(asset model.Asset) string {
	parts := []string{
		optionalString(asset.Vendor),
		optionalString(asset.Product),
		optionalString(asset.DeviceModel),
	}
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			values = append(values, strings.TrimSpace(part))
		}
	}
	return strings.Join(values, " ")
}

// normalizeAssetDisplayFields normalizes user-visible asset fields before persistence.
func normalizeAssetDisplayFields(asset model.Asset) model.Asset {
	asset.Name = normalizeDisplayText(asset.Name)
	asset.Type = normalizeDisplayText(asset.Type)
	asset.OperatingSystem = normalizeOptionalDisplayText(asset.OperatingSystem)
	asset.Vendor = normalizeOptionalDisplayText(asset.Vendor)
	asset.Product = normalizeOptionalDisplayText(asset.Product)
	asset.DeviceModel = normalizeOptionalDisplayText(asset.DeviceModel)
	asset.Owner = normalizeDisplayText(asset.Owner)
	asset.Criticality = normalizeDisplayText(asset.Criticality)
	return asset
}

// validateAsset validates the fields required to create or update an asset.
func validateAsset(asset model.Asset) error {
	if strings.TrimSpace(asset.Name) == "" ||
		strings.TrimSpace(asset.Type) == "" ||
		strings.TrimSpace(asset.Owner) == "" ||
		strings.TrimSpace(asset.Criticality) == "" {
		return ErrInvalidAssetData
	}
	return nil
}

// translateAssetRepositoryError maps repository errors to asset service errors.
func translateAssetRepositoryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, assetrepository.ErrRecordNotFound):
		return fmt.Errorf("%w: %w", ErrAssetNotFound, err)
	case errors.Is(err, assetrepository.ErrPrimaryKeyViolation):
		return fmt.Errorf("%w: %w", ErrDuplicateAsset, err)
	case errors.Is(err, assetrepository.ErrNotNullViolation),
		errors.Is(err, assetrepository.ErrForeignKeyViolation):
		return fmt.Errorf("%w: %w", ErrInvalidAssetData, err)
	default:
		return fmt.Errorf("%w: %w", ErrAssetDependency, err)
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

// optionalString returns a trimmed value for optional strings.
func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

// decodeJSONOnly decodes a JSON object after stripping optional markdown fences.
func decodeJSONOnly(raw string, target any) error {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.TrimPrefix(trimmed, "```json")
	trimmed = strings.TrimPrefix(trimmed, "```")
	trimmed = strings.TrimSuffix(trimmed, "```")
	trimmed = strings.TrimSpace(trimmed)
	if trimmed == "" {
		return fmt.Errorf("%w: empty ai extraction response", ErrAssetExternalService)
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(trimmed)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: decode ai extraction response", ErrAssetExternalService)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: decode ai extraction response", ErrAssetExternalService)
	}
	return nil
}

// stringPtrFromValue returns nil for blank values and a pointer otherwise.
func stringPtrFromValue(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

// authenticatedUserID returns the authenticated user ID from request context.
func authenticatedUserID(ec *appcontext.GinContext) (string, error) {
	if ec == nil {
		return "", ErrAssetPermissionDenied
	}

	userID, err := ec.UserID()
	if err != nil {
		return "", err
	}

	return userID, nil
}

// normalizeDisplayText trims, title-cases, and preserves known acronyms for human-facing labels.
func normalizeDisplayText(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}

	words := strings.Fields(trimmed)
	for index, word := range words {
		words[index] = normalizeDisplayWord(word)
	}

	return strings.Join(words, " ")
}

// normalizeOptionalDisplayText normalizes an optional human-facing label while preserving nil for empty values.
func normalizeOptionalDisplayText(value *string) *string {
	if value == nil {
		return nil
	}

	normalized := normalizeDisplayText(*value)
	if normalized == "" {
		return nil
	}

	return &normalized
}

// normalizeDisplayWord formats a single display word while preserving known acronyms and intentional casing.
func normalizeDisplayWord(word string) string {
	if word == "" {
		return ""
	}

	lower := strings.ToLower(word)
	if acronym, ok := displayAcronyms[lower]; ok {
		return acronym
	}
	if isAllUpper(word) {
		return word
	}
	if hasMixedCase(word) {
		return word
	}

	runes := []rune(lower)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

// isAllUpper reports whether all letters in value are uppercase.
func isAllUpper(value string) bool {
	hasLetter := false
	for _, r := range value {
		if !unicode.IsLetter(r) {
			continue
		}
		hasLetter = true
		if unicode.IsLower(r) {
			return false
		}
	}
	return hasLetter
}

// hasMixedCase reports whether a value already contains mixed letter casing.
func hasMixedCase(value string) bool {
	hasUpper := false
	hasLower := false
	for _, r := range value {
		if unicode.IsUpper(r) {
			hasUpper = true
		}
		if unicode.IsLower(r) {
			hasLower = true
		}
	}
	return hasUpper && hasLower
}

// sanitizeAIIngestionText normalizes pasted asset text and rejects obvious prompt-injection attempts.
func sanitizeAIIngestionText(rawText string) (string, error) {
	if !utf8.ValidString(rawText) {
		return "", ErrInvalidAssetText
	}

	trimmed := strings.TrimSpace(rawText)
	if trimmed == "" {
		return "", ErrInvalidAssetText
	}
	if len(trimmed) > aiIngestionMaxBytes || utf8.RuneCountInString(trimmed) > aiIngestionMaxRunes {
		return "", ErrInvalidAssetText
	}
	if aiPromptInjectionPattern.MatchString(trimmed) {
		return "", ErrInvalidAssetText
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
