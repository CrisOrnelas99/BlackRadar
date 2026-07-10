// Package service provides validation, context, and repository error helpers for application services.
package service

import (
	"regexp"
	"strings"

	"blackradar/api/model"
)

// AssetFingerprint captures the normalized product signals derived from an asset.
type AssetFingerprint struct {
	Vendor          string
	Product         string
	Version         string
	OperatingSystem string
	DeviceModel     string
	AssetName       string
	AssetType       string
	Canonical       string
}

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
)

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

func firstRegexGroup(pattern *regexp.Regexp, value string, groupIndex int) string {
	matches := pattern.FindStringSubmatch(value)
	if len(matches) <= groupIndex {
		return ""
	}
	return normalizeFingerprintValue(matches[groupIndex])
}

func normalizeVendorHint(value string) string {
	value = normalizeFingerprintValue(value)
	for _, suffix := range []string{" software foundation", " project", " vendor", " team", " foundation"} {
		if strings.HasSuffix(value, suffix) {
			value = strings.TrimSpace(strings.TrimSuffix(value, suffix))
		}
	}
	return value
}

func normalizeFingerprintLine(value string) string {
	value = strings.ReplaceAll(value, "\t", " ")
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	fields := strings.Fields(value)
	return strings.Join(fields, " ")
}

func normalizeFingerprintValue(value string) string {
	value = normalizeFingerprintLine(value)
	if value == "" {
		return ""
	}

	value = strings.Trim(value, `"'`+"`")
	value = strings.Trim(value, ".,;")
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeOptionalFingerprintValue(value *string) string {
	if value == nil {
		return ""
	}
	return normalizeFingerprintValue(*value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

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
