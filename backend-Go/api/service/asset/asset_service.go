// Package service provides asset-related application services.
package service

import (
	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/dto"
	"secureops/backend-go/api/model"
	baserepository "secureops/backend-go/api/repository"
	baseservice "secureops/backend-go/api/service"
)

type assetServiceImpl struct {
	assetRepository         baserepository.AssetRepository
	vulnerabilityRepository baserepository.VulnerabilityRepository
	nvdLookupService        baseservice.NVDLookupService
}

// NewAssetService creates an asset service backed by the supplied repository.
func NewAssetService(assetRepository baserepository.AssetRepository, vulnerabilityRepository baserepository.VulnerabilityRepository, nvdLookupService baseservice.NVDLookupService) baseservice.AssetService {
	return &assetServiceImpl{
		assetRepository:         assetRepository,
		vulnerabilityRepository: vulnerabilityRepository,
		nvdLookupService:        nvdLookupService,
	}
}

// GetAllAssets returns all assets owned by the authenticated user.
func (s *assetServiceImpl) GetAllAssets(ec *appcontext.GinContext) ([]model.Asset, error) {
	userID, err := baseservice.AuthenticatedUserID(ec)
	if err != nil {
		return nil, err
	}
	assets, err := s.assetRepository.FindAllByUser(ec, userID)
	return assets, baseservice.TranslateRepositoryError(err)
}

// GetAsset returns a single asset owned by the authenticated user.
func (s *assetServiceImpl) GetAsset(ec *appcontext.GinContext, id int64) (model.Asset, error) {
	userID, err := baseservice.AuthenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset, err := s.assetRepository.FindByIDForUser(ec, id, userID)
	return asset, baseservice.TranslateRepositoryError(err)
}

// CreateAsset validates and saves a new asset for the authenticated user.
func (s *assetServiceImpl) CreateAsset(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error) {
	if err := baseservice.ValidateAsset(asset); err != nil {
		return model.Asset{}, err
	}

	userID, err := baseservice.AuthenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset.UserID = userID

	created, err := s.assetRepository.Save(ec, asset)
	return created, baseservice.TranslateRepositoryError(err)
}

// UpdateAsset validates and updates an existing asset for the authenticated user.
func (s *assetServiceImpl) UpdateAsset(ec *appcontext.GinContext, id int64, asset model.Asset) (model.Asset, error) {
	if err := baseservice.ValidateAsset(asset); err != nil {
		return model.Asset{}, err
	}

	userID, err := baseservice.AuthenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}

	updated, err := s.assetRepository.UpdateForUser(ec, id, userID, asset)
	return updated, baseservice.TranslateRepositoryError(err)
}

// DeleteAsset removes an asset owned by the authenticated user.
func (s *assetServiceImpl) DeleteAsset(ec *appcontext.GinContext, id int64) (model.Asset, error) {
	userID, err := baseservice.AuthenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset, err := s.assetRepository.DeleteForUser(ec, id, userID)
	return asset, baseservice.TranslateRepositoryError(err)
}

// AssignVulnerability attaches a vulnerability to an asset owned by the authenticated user.
func (s *assetServiceImpl) AssignVulnerability(ec *appcontext.GinContext, assetID int64, vulnerabilityID int64) (model.Asset, error) {
	userID, err := baseservice.AuthenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset, err := s.assetRepository.AssignVulnerabilityForUser(ec, assetID, userID, vulnerabilityID)
	return asset, baseservice.TranslateRepositoryError(err)
}

// AssignVulnerabilityByCVE looks up or stores a local vulnerability by CVE ID, then assigns it to the asset.
func (s *assetServiceImpl) AssignVulnerabilityByCVE(ec *appcontext.GinContext, assetID int64, cveID string) (model.Asset, error) {
	userID, err := baseservice.AuthenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}

	asset, err := s.assetRepository.FindByIDForUser(ec, assetID, userID)
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

	existingVulnerability, err := s.vulnerabilityRepository.FindByCVEIDForUser(ec, normalizedCVEID, userID)
	if err != nil && err != baserepository.ErrVulnerabilityNotFound {
		return model.Asset{}, baseservice.TranslateRepositoryError(err)
	}

	vulnerability, err := s.saveNVDVulnerability(ec, userID, lookup, existingVulnerability)
	if err != nil {
		return model.Asset{}, err
	}

	asset, err = s.assetRepository.AssignVulnerabilityForUser(ec, asset.ID, userID, vulnerability.ID)
	if err != nil {
		return model.Asset{}, baseservice.TranslateRepositoryError(err)
	}

	return asset, nil
}

// RemoveVulnerability removes a vulnerability from an asset owned by the authenticated user.
func (s *assetServiceImpl) RemoveVulnerability(ec *appcontext.GinContext, assetID int64, vulnerabilityID int64) (model.Asset, error) {
	userID, err := baseservice.AuthenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset, err := s.assetRepository.RemoveVulnerabilityForUser(ec, assetID, userID, vulnerabilityID)
	return asset, baseservice.TranslateRepositoryError(err)
}

func (s *assetServiceImpl) saveNVDVulnerability(ec *appcontext.GinContext, userID int64, response dto.CVELookupResponse, existing model.Vulnerability) (model.Vulnerability, error) {
	vulnerability := model.Vulnerability{
		UserID:      userID,
		CVEID:       response.CVEID,
		Title:       response.Title,
		Severity:    baseservice.NormalizeSeverity(response.Severity),
		Description: response.Description,
		Status:      "Open",
	}

	if existing.ID > 0 {
		return s.vulnerabilityRepository.UpdateForUser(ec, existing.ID, userID, vulnerability)
	}

	return s.vulnerabilityRepository.Save(ec, vulnerability)
}
