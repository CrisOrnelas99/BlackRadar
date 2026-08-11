// Package service support contains asset validation and normalization helpers.
package service

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"blackradar/api/model"
	platformdb "blackradar/api/platform/db"
	appcontext "blackradar/api/platform/requestcontext"
	assetrepository "blackradar/api/repository/asset"
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

func runAssetAuditTransaction(ec *appcontext.GinContext, operation func(*appcontext.GinContext) error) error {
	return platformdb.WithinRequestTransaction(ec, operation)
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

// optionalString returns a trimmed value for optional strings.
func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
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
