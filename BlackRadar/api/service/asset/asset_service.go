// Package service provides asset-related application services.
package service

import (
	"encoding/json"
	"fmt"
	"strings"

	"blackradar/api/controller/dto"
	"blackradar/api/model"
	baserepository "blackradar/api/repository"
	appcontext "blackradar/api/requestContext"
	baseservice "blackradar/api/service"
	aiservice "blackradar/api/service/ai"
)

type assetServiceImpl struct {
	assetRepository         baserepository.AssetRepository
	vulnerabilityRepository baserepository.VulnerabilityRepository
	nvdLookupService        baseservice.NVDLookupService
	textAI                  aiservice.TextGenerationService
}

// NewAssetService creates an asset service backed by the supplied repository.
func NewAssetService(assetRepository baserepository.AssetRepository, vulnerabilityRepository baserepository.VulnerabilityRepository, nvdLookupService baseservice.NVDLookupService, textAI aiservice.TextGenerationService) baseservice.AssetService {
	return &assetServiceImpl{
		assetRepository:         assetRepository,
		vulnerabilityRepository: vulnerabilityRepository,
		nvdLookupService:        nvdLookupService,
		textAI:                  textAI,
	}
}

// GetAllAssets returns all assets owned by the authenticated user.
func (s *assetServiceImpl) GetAllAssets(ec *appcontext.GinContext) ([]model.Asset, error) {
	organizationID, err := baseservice.AuthenticatedOrganizationID(ec)
	if err != nil {
		return nil, err
	}
	assets, err := s.assetRepository.FindAllByOrganization(ec, organizationID)
	return assets, baseservice.TranslateRepositoryError(err)
}

// GetAsset returns a single asset owned by the authenticated user.
func (s *assetServiceImpl) GetAsset(ec *appcontext.GinContext, id string) (model.Asset, error) {
	organizationID, err := baseservice.AuthenticatedOrganizationID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset, err := s.assetRepository.FindByIDForOrganization(ec, id, organizationID)
	return asset, baseservice.TranslateRepositoryError(err)
}

// CreateAsset validates and saves a new asset for the authenticated user.
func (s *assetServiceImpl) CreateAsset(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error) {
	asset = normalizeAssetDisplayFields(asset)
	if err := baseservice.ValidateAsset(asset); err != nil {
		return model.Asset{}, err
	}

	userID, err := baseservice.AuthenticatedUserID(ec)
	organizationID, orgErr := baseservice.AuthenticatedOrganizationID(ec)
	if orgErr != nil {
		return model.Asset{}, orgErr
	}
	if err != nil {
		return model.Asset{}, err
	}

	exists, err := s.assetRepository.ExistsBySignatureForOrganization(ec, asset, organizationID)
	if err != nil {
		return model.Asset{}, baseservice.TranslateRepositoryError(err)
	}
	if exists {
		return model.Asset{}, baseservice.ErrConflict
	}

	asset.UserID = userID
	asset.OrganizationID = organizationID

	created, err := s.assetRepository.Save(ec, asset)
	return created, baseservice.TranslateRepositoryError(err)
}

// CreateAssetFromAI extracts an asset from raw text and creates it without running vulnerability matching.
func (s *assetServiceImpl) CreateAssetFromAI(ec *appcontext.GinContext, rawText string) (model.Asset, error) {
	if s.textAI == nil {
		return model.Asset{}, baseservice.ErrExternalService
	}

	sanitizedText, err := baseservice.SanitizeAIIngestionText(rawText)
	if err != nil {
		return model.Asset{}, err
	}

	response, err := s.textAI.GenerateText(ec.RequestContext(), aiservice.BuildAssetCreationExtractionRequest(sanitizedText))
	if err != nil {
		return model.Asset{}, fmt.Errorf("%w: asset extraction failed", baseservice.ErrExternalService)
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
	if err := baseservice.ValidateAsset(asset); err != nil {
		return model.Asset{}, err
	}

	organizationID, err := baseservice.AuthenticatedOrganizationID(ec)
	if err != nil {
		return model.Asset{}, err
	}

	updated, err := s.assetRepository.UpdateForOrganization(ec, id, organizationID, asset)
	return updated, baseservice.TranslateRepositoryError(err)
}

// DeleteAsset removes an asset owned by the authenticated user.
func (s *assetServiceImpl) DeleteAsset(ec *appcontext.GinContext, id string) (model.Asset, error) {
	organizationID, err := baseservice.AuthenticatedOrganizationID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset, err := s.assetRepository.DeleteForOrganization(ec, id, organizationID)
	return asset, baseservice.TranslateRepositoryError(err)
}

// AssignVulnerability attaches a vulnerability to an asset owned by the authenticated user.
func (s *assetServiceImpl) AssignVulnerability(ec *appcontext.GinContext, assetID string, vulnerabilityID string) (model.Asset, error) {
	role := ""
	if ec != nil {
		role = ec.UserRole()
	}
	if !baseservice.CanManageVulnerabilities(role) {
		return model.Asset{}, baseservice.ErrForbidden
	}

	organizationID, err := baseservice.AuthenticatedOrganizationID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset, err := s.assetRepository.AssignVulnerabilityForOrganization(ec, assetID, organizationID, vulnerabilityID)
	return asset, baseservice.TranslateRepositoryError(err)
}

// AssignVulnerabilityByCVE looks up or stores a local vulnerability by CVE ID, then assigns it to the asset.
func (s *assetServiceImpl) AssignVulnerabilityByCVE(ec *appcontext.GinContext, assetID string, cveID string) (model.Asset, error) {
	role := ""
	if ec != nil {
		role = ec.UserRole()
	}
	if !baseservice.CanManageVulnerabilities(role) {
		return model.Asset{}, baseservice.ErrForbidden
	}

	organizationID, err := baseservice.AuthenticatedOrganizationID(ec)
	if err != nil {
		return model.Asset{}, err
	}

	asset, err := s.assetRepository.FindByIDForOrganization(ec, assetID, organizationID)
	if err != nil {
		return model.Asset{}, baseservice.TranslateRepositoryError(err)
	}

	normalizedCVEID := baseservice.NormalizeCVEID(cveID)
	if err := baseservice.ValidateCVEID(normalizedCVEID); err != nil {
		return model.Asset{}, err
	}

	lookup, err := s.nvdLookupService.LookupCVE(ec, normalizedCVEID)
	if err != nil {
		return model.Asset{}, err
	}

	existingVulnerability, err := s.vulnerabilityRepository.FindByCVEIDForOrganization(ec, normalizedCVEID, organizationID)
	if err != nil && err != baserepository.ErrVulnerabilityNotFound {
		return model.Asset{}, baseservice.TranslateRepositoryError(err)
	}

	vulnerability, err := s.saveNVDVulnerability(ec, organizationID, lookup, existingVulnerability)
	if err != nil {
		return model.Asset{}, err
	}

	asset, err = s.assetRepository.AssignVulnerabilityForOrganization(ec, asset.ID, organizationID, vulnerability.ID)
	if err != nil {
		return model.Asset{}, baseservice.TranslateRepositoryError(err)
	}

	return asset, nil
}

// RemoveVulnerability removes a vulnerability from an asset owned by the authenticated user.
func (s *assetServiceImpl) RemoveVulnerability(ec *appcontext.GinContext, assetID string, vulnerabilityID string) (model.Asset, error) {
	role := ""
	if ec != nil {
		role = ec.UserRole()
	}
	if !baseservice.CanManageVulnerabilities(role) {
		return model.Asset{}, baseservice.ErrForbidden
	}

	organizationID, err := baseservice.AuthenticatedOrganizationID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset, err := s.assetRepository.RemoveVulnerabilityForOrganization(ec, assetID, organizationID, vulnerabilityID)
	return asset, baseservice.TranslateRepositoryError(err)
}

func (s *assetServiceImpl) saveNVDVulnerability(ec *appcontext.GinContext, organizationID string, response dto.CVELookupResponse, existing model.Vulnerability) (model.Vulnerability, error) {
	vulnerability := model.Vulnerability{
		OrganizationID: organizationID,
		UserID:         ec.UserID(),
		CVEID:          response.CVEID,
		Title:          response.Title,
		Severity:       baseservice.NormalizeSeverity(response.Severity),
		Description:    response.Description,
		Status:         "Open",
	}

	if existing.ID != "" {
		return s.vulnerabilityRepository.UpdateForOrganization(ec, existing.ID, organizationID, vulnerability)
	}

	return s.vulnerabilityRepository.Save(ec, vulnerability)
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
		return model.Asset{}, baseservice.ErrInvalidRequestData
	}

	return asset, nil
}

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

func normalizeAssetDisplayFields(asset model.Asset) model.Asset {
	asset.Name = baseservice.NormalizeDisplayText(asset.Name)
	asset.Type = baseservice.NormalizeDisplayText(asset.Type)
	asset.OperatingSystem = baseservice.NormalizeOptionalDisplayText(asset.OperatingSystem)
	asset.Vendor = baseservice.NormalizeOptionalDisplayText(asset.Vendor)
	asset.Product = baseservice.NormalizeOptionalDisplayText(asset.Product)
	asset.DeviceModel = baseservice.NormalizeOptionalDisplayText(asset.DeviceModel)
	asset.Owner = baseservice.NormalizeDisplayText(asset.Owner)
	asset.Criticality = baseservice.NormalizeDisplayText(asset.Criticality)
	return asset
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func decodeJSONOnly(raw string, target any) error {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.TrimPrefix(trimmed, "```json")
	trimmed = strings.TrimPrefix(trimmed, "```")
	trimmed = strings.TrimSuffix(trimmed, "```")
	trimmed = strings.TrimSpace(trimmed)
	if trimmed == "" {
		return fmt.Errorf("%w: empty ai extraction response", baseservice.ErrExternalService)
	}
	if err := json.Unmarshal([]byte(trimmed), target); err != nil {
		return fmt.Errorf("%w: decode ai extraction response", baseservice.ErrExternalService)
	}
	return nil
}

func stringPtrFromValue(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}
