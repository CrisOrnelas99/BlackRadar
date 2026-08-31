// Package service support contains asset validation and normalization helpers.
package service

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"blackradar/api/common/pagination"
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

const (
	maxAssetDescriptionLength = 5000
	maxAssetListTextLength    = 200
	defaultAssetOwner         = "Unassigned"
)

func normalizeAssetListQuery(query model.AssetListQuery) (model.AssetListQuery, error) {
	query.Pagination.PageSize = pagination.DefaultPageSize
	if err := query.Pagination.Validate(); err != nil {
		return model.AssetListQuery{}, fmt.Errorf("%w: %w", ErrInvalidAssetListQuery, err)
	}

	query.Search = strings.TrimSpace(query.Search)
	query.Criticality = strings.TrimSpace(query.Criticality)
	query.RiskLevel = strings.TrimSpace(query.RiskLevel)
	query.Type = strings.TrimSpace(query.Type)
	query.Owner = strings.TrimSpace(query.Owner)
	query.OperatingSystem = strings.TrimSpace(query.OperatingSystem)
	query.Vendor = strings.TrimSpace(query.Vendor)
	query.Product = strings.TrimSpace(query.Product)
	query.Version = strings.TrimSpace(query.Version)

	if assetListTextTooLong(query) || (query.VulnerabilityValue != nil && *query.VulnerabilityValue < 0) {
		return model.AssetListQuery{}, ErrInvalidAssetListQuery
	}

	switch query.VulnerabilityMode {
	case "", model.AssetVulnerabilityFilterAny:
		query.VulnerabilityMode = model.AssetVulnerabilityFilterAny
	case model.AssetVulnerabilityFilterAtLeast, model.AssetVulnerabilityFilterAtMost, model.AssetVulnerabilityFilterExactly:
		if query.VulnerabilityValue == nil {
			return model.AssetListQuery{}, ErrInvalidAssetListQuery
		}
	default:
		return model.AssetListQuery{}, ErrInvalidAssetListQuery
	}

	switch query.SortField {
	case "", model.AssetSortName:
		query.SortField = model.AssetSortName
	case model.AssetSortCriticality, model.AssetSortRiskLevel, model.AssetSortVulnerabilityCount,
		model.AssetSortType, model.AssetSortOwner, model.AssetSortOperatingSystem,
		model.AssetSortVendor, model.AssetSortProduct, model.AssetSortVersion:
	default:
		return model.AssetListQuery{}, ErrInvalidAssetListQuery
	}

	switch query.SortDirection {
	case "", model.AssetSortAscending:
		query.SortDirection = model.AssetSortAscending
	case model.AssetSortDescending:
	default:
		return model.AssetListQuery{}, ErrInvalidAssetListQuery
	}

	return query, nil
}

func assetListTextTooLong(query model.AssetListQuery) bool {
	values := []string{query.Search, query.Criticality, query.RiskLevel, query.Type, query.Owner, query.OperatingSystem, query.Vendor, query.Product, query.Version}
	for _, value := range values {
		if len(value) > maxAssetListTextLength {
			return true
		}
	}
	return false
}

func runAssetAuditTransaction(ec *appcontext.GinContext, operation func(*appcontext.GinContext) error) error {
	return platformdb.WithinRequestTransaction(ec, operation)
}

// normalizeAssetDisplayFields normalizes user-visible asset fields before persistence.
func normalizeAssetDisplayFields(asset model.Asset) model.Asset {
	asset.Name = normalizeDisplayText(asset.Name)
	asset.Type = normalizeDisplayText(asset.Type)
	asset.Description = normalizeOptionalText(asset.Description)
	asset.OperatingSystem = normalizeOptionalDisplayText(asset.OperatingSystem)
	asset.Vendor = normalizeOptionalDisplayText(asset.Vendor)
	asset.Product = normalizeOptionalDisplayText(asset.Product)
	asset.Version = normalizeOptionalText(asset.Version)
	asset.DeviceModel = normalizeOptionalDisplayText(asset.DeviceModel)
	asset.Owner = normalizeDisplayText(asset.Owner)
	if asset.Owner == "" {
		asset.Owner = defaultAssetOwner
	}
	asset.Criticality = normalizeDisplayText(asset.Criticality)
	return asset
}

func normalizeOptionalText(value *string) *string {
	if value == nil {
		return nil
	}

	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}

	return &trimmed
}

// validateAsset validates the fields required to create or update an asset.
func validateAsset(asset model.Asset) error {
	if asset.Description != nil && len(*asset.Description) > maxAssetDescriptionLength {
		return ErrInvalidAssetData
	}

	if strings.TrimSpace(asset.Name) == "" ||
		strings.TrimSpace(asset.Type) == "" ||
		strings.TrimSpace(asset.Criticality) == "" ||
		optionalString(asset.Vendor) == "" ||
		optionalString(asset.Product) == "" ||
		optionalString(asset.Version) == "" {
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
