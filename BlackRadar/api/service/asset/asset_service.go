// Package service provides asset-related application services.
package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"blackradar/api/controller/dto"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
	baserepository "blackradar/api/repository"
	assetrepository "blackradar/api/repository/asset"
	vulnerabilityrepository "blackradar/api/repository/vulnerability"
	baseservice "blackradar/api/service"
	promptservice "blackradar/api/service/prompt"
)

var (
	cveIDPattern             = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	aiPromptInjectionPattern = regexp.MustCompile(`(?i)(ignore (all )?previous instructions|system prompt|developer message|reveal the prompt|bypass policy|prompt injection|jailbreak|do anything now)`)
)

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

type assetServiceImpl struct {
	assetRepository         baserepository.AssetRepository
	vulnerabilityRepository baserepository.VulnerabilityRepository
	nvdLookupService        baseservice.NVDLookupService
	textAI                  baseservice.TextGenerationService
}

// NewAssetService creates an asset service backed by the supplied repository.
func NewAssetService(assetRepository baserepository.AssetRepository, vulnerabilityRepository baserepository.VulnerabilityRepository, nvdLookupService baseservice.NVDLookupService, textAI baseservice.TextGenerationService) baseservice.AssetService {
	return &assetServiceImpl{
		assetRepository:         assetRepository,
		vulnerabilityRepository: vulnerabilityRepository,
		nvdLookupService:        nvdLookupService,
		textAI:                  textAI,
	}
}

// GetAllAssets returns all assets owned by the authenticated user.
func (s *assetServiceImpl) GetAllAssets(ec *appcontext.GinContext) ([]model.Asset, error) {
	userID, err := authenticatedUserID(ec)
	if err != nil {
		return nil, err
	}
	assets, err := s.assetRepository.FindAllByUser(ec, userID)
	return assets, translateAssetRepositoryError(err)
}

// GetAsset returns a single asset owned by the authenticated user.
func (s *assetServiceImpl) GetAsset(ec *appcontext.GinContext, id string) (model.Asset, error) {
	userID, err := authenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset, err := s.assetRepository.FindByIDForUser(ec, id, userID)
	if errors.Is(err, assetrepository.ErrAssetNotFound) {
		return model.Asset{}, ErrAssetNotFound
	}
	return asset, translateAssetRepositoryError(err)
}

// CreateAsset validates and saves a new asset for the authenticated user.
func (s *assetServiceImpl) CreateAsset(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error) {
	asset = normalizeAssetDisplayFields(asset)
	if err := validateAsset(asset); err != nil {
		return model.Asset{}, ErrInvalidAssetData
	}

	userID, err := authenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}

	exists, err := s.assetRepository.ExistsBySignatureForUser(ec, asset, userID)
	if err != nil {
		return model.Asset{}, translateAssetRepositoryError(err)
	}
	if exists {
		return model.Asset{}, ErrDuplicateAsset
	}

	asset.UserID = userID

	created, err := s.assetRepository.Save(ec, asset)
	return created, translateAssetRepositoryError(err)
}

// CreateAssetFromAI extracts an asset from raw text and creates it without running vulnerability matching.
func (s *assetServiceImpl) CreateAssetFromAI(ec *appcontext.GinContext, rawText string) (model.Asset, error) {
	if s.textAI == nil {
		return model.Asset{}, ErrAssetExternalService
	}

	sanitizedText, err := sanitizeAIIngestionText(rawText)
	if err != nil {
		return model.Asset{}, ErrInvalidAssetText
	}

	response, err := s.textAI.GenerateText(ec.RequestContext(), promptservice.BuildAssetCreationExtractionRequest(sanitizedText))
	if err != nil {
		return model.Asset{}, fmt.Errorf("%w: asset AI extraction failed: %w", ErrAssetExternalService, err)
	}

	asset, err := assetFromAIExtraction(response.Text)
	if err != nil {
		return model.Asset{}, err
	}

	return s.CreateAsset(ec, asset)
}

// UpdateAsset validates and updates an existing asset for the authenticated user.
func (s *assetServiceImpl) UpdateAsset(ec *appcontext.GinContext, id string, asset model.Asset) (model.Asset, error) {
	asset = normalizeAssetDisplayFields(asset)
	if err := validateAsset(asset); err != nil {
		return model.Asset{}, ErrInvalidAssetData
	}

	userID, err := authenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}

	updated, err := s.assetRepository.UpdateForUser(ec, id, userID, asset)
	if errors.Is(err, assetrepository.ErrAssetNotFound) {
		return model.Asset{}, ErrAssetNotFound
	}
	return updated, translateAssetRepositoryError(err)
}

// DeleteAsset removes an asset owned by the authenticated user.
func (s *assetServiceImpl) DeleteAsset(ec *appcontext.GinContext, id string) (model.Asset, error) {
	userID, err := authenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset, err := s.assetRepository.DeleteForUser(ec, id, userID)
	if errors.Is(err, assetrepository.ErrAssetNotFound) {
		return model.Asset{}, ErrAssetNotFound
	}
	return asset, translateAssetRepositoryError(err)
}

// AssignVulnerability attaches a vulnerability to an asset owned by the authenticated user.
func (s *assetServiceImpl) AssignVulnerability(ec *appcontext.GinContext, assetID string, vulnerabilityID string) (model.Asset, error) {
	role, err := authenticatedRole(ec)
	if err != nil {
		return model.Asset{}, ErrAssetPermissionDenied
	}
	if !canManageVulnerabilities(role) {
		return model.Asset{}, ErrVulnerabilityManagementDenied
	}

	userID, err := authenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset, err := s.assetRepository.AssignVulnerabilityForUser(ec, assetID, userID, vulnerabilityID)
	switch {
	case errors.Is(err, assetrepository.ErrAssetNotFound):
		return model.Asset{}, ErrAssetNotFound
	case errors.Is(err, assetrepository.ErrVulnerabilityNotFound):
		return model.Asset{}, ErrAssetVulnerabilityNotFound
	case errors.Is(err, assetrepository.ErrDuplicateAssignment):
		return model.Asset{}, ErrDuplicateAssetVulnerability
	default:
		return asset, translateAssetRepositoryError(err)
	}
}

// AssignVulnerabilityByCVE looks up or stores a local vulnerability by CVE ID, then assigns it to the asset.
func (s *assetServiceImpl) AssignVulnerabilityByCVE(ec *appcontext.GinContext, assetID string, cveID string) (model.Asset, error) {
	role, err := authenticatedRole(ec)
	if err != nil {
		return model.Asset{}, ErrAssetPermissionDenied
	}
	if !canManageVulnerabilities(role) {
		return model.Asset{}, ErrVulnerabilityManagementDenied
	}

	userID, err := authenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}

	normalizedCVEID := normalizeCVEID(cveID)
	if err := validateCVEID(normalizedCVEID); err != nil {
		return model.Asset{}, ErrInvalidAssetCVEID
	}

	asset, err := s.assetRepository.FindByIDForUser(ec, assetID, userID)
	if err != nil {
		if errors.Is(err, assetrepository.ErrAssetNotFound) {
			return model.Asset{}, ErrAssetNotFound
		}
		return model.Asset{}, translateAssetRepositoryError(err)
	}

	lookup, err := s.nvdLookupService.LookupCVE(ec, normalizedCVEID)
	if err != nil {
		return model.Asset{}, err
	}

	existingVulnerability, err := s.vulnerabilityRepository.FindByCVEIDForUser(ec, normalizedCVEID, userID)
	if err != nil && !errors.Is(err, vulnerabilityrepository.ErrVulnerabilityNotFound) {
		return model.Asset{}, translateAssetRepositoryError(err)
	}

	vulnerability, err := s.saveNVDVulnerability(ec, userID, lookup, existingVulnerability)
	if err != nil {
		return model.Asset{}, err
	}

	asset, err = s.assetRepository.AssignVulnerabilityForUser(ec, asset.ID, userID, vulnerability.ID)
	if err != nil {
		if errors.Is(err, assetrepository.ErrDuplicateAssignment) {
			return model.Asset{}, ErrDuplicateAssetVulnerability
		}
		return model.Asset{}, translateAssetRepositoryError(err)
	}

	return asset, nil
}

// RemoveVulnerability removes a vulnerability from an asset owned by the authenticated user.
func (s *assetServiceImpl) RemoveVulnerability(ec *appcontext.GinContext, assetID string, vulnerabilityID string) (model.Asset, error) {
	role, err := authenticatedRole(ec)
	if err != nil {
		return model.Asset{}, ErrAssetPermissionDenied
	}
	if !canManageVulnerabilities(role) {
		return model.Asset{}, ErrVulnerabilityManagementDenied
	}

	userID, err := authenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset, err := s.assetRepository.RemoveVulnerabilityForUser(ec, assetID, userID, vulnerabilityID)
	switch {
	case errors.Is(err, assetrepository.ErrAssetNotFound):
		return model.Asset{}, ErrAssetNotFound
	case errors.Is(err, assetrepository.ErrVulnerabilityNotFound):
		return model.Asset{}, ErrAssetVulnerabilityNotFound
	default:
		return asset, translateAssetRepositoryError(err)
	}
}

// saveNVDVulnerability creates or updates a local vulnerability from an NVD response.
func (s *assetServiceImpl) saveNVDVulnerability(ec *appcontext.GinContext, userID string, response dto.CVELookupResponse, existing model.Vulnerability) (model.Vulnerability, error) {
	vulnerability := model.Vulnerability{
		UserID:      userID,
		CVEID:       response.CVEID,
		Title:       response.Title,
		Severity:    normalizeSeverity(response.Severity),
		Description: response.Description,
		Status:      "Open",
	}

	if existing.ID != "" {
		updated, err := s.vulnerabilityRepository.UpdateForUser(ec, existing.ID, userID, vulnerability)
		return updated, translateAssetRepositoryError(err)
	}

	created, err := s.vulnerabilityRepository.Save(ec, vulnerability)
	return created, translateAssetRepositoryError(err)
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

// translateAssetRepositoryError maps asset repository errors to asset service sentinels.
func translateAssetRepositoryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, assetrepository.ErrAssetNotFound):
		return fmt.Errorf("%w: %w", ErrAssetNotFound, err)
	case errors.Is(err, assetrepository.ErrVulnerabilityNotFound),
		errors.Is(err, vulnerabilityrepository.ErrVulnerabilityNotFound):
		return fmt.Errorf("%w: %w", ErrAssetVulnerabilityNotFound, err)
	case errors.Is(err, assetrepository.ErrDuplicateAssignment):
		return fmt.Errorf("%w: %w", ErrDuplicateAssetVulnerability, err)
	case errors.Is(err, assetrepository.ErrPrimaryKeyConflict):
		return fmt.Errorf("%w: %w", ErrDuplicateAsset, err)
	case errors.Is(err, assetrepository.ErrInvalidData),
		errors.Is(err, assetrepository.ErrInvalidReference):
		return fmt.Errorf("%w: %w", ErrInvalidAssetData, err)
	default:
		return fmt.Errorf("%w: %w", ErrAssetInternal, err)
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
	if err := json.Unmarshal([]byte(trimmed), target); err != nil {
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

// authenticatedRole returns the authenticated role from request context.
func authenticatedRole(ec *appcontext.GinContext) (string, error) {
	if ec == nil {
		return "", ErrAssetPermissionDenied
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

// normalizeCVEID trims and uppercases a CVE identifier before lookup.
func normalizeCVEID(cveID string) string {
	return strings.ToUpper(strings.TrimSpace(cveID))
}

// validateCVEID verifies the identifier is safe to use with the NVD CVE API.
func validateCVEID(cveID string) error {
	if !cveIDPattern.MatchString(normalizeCVEID(cveID)) {
		return ErrInvalidAssetCVEID
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
