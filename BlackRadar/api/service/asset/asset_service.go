// Package service provides asset-related application services.
package service

import (
	"fmt"

	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
	assetrepository "blackradar/api/repository/asset"
	textgenerationservice "blackradar/api/service/text_generation"
)

type assetServiceImpl struct {
	assetRepository assetrepository.AssetRepositoryInterface
	textAI          textgenerationservice.TextGenerationService
}

// NewAssetService creates an asset service backed by the supplied repository.
func NewAssetService(assetRepository assetrepository.AssetRepositoryInterface, textAI textgenerationservice.TextGenerationService) *assetServiceImpl {
	return &assetServiceImpl{
		assetRepository: assetRepository,
		textAI:          textAI,
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

	response, err := s.textAI.GenerateText(ec.RequestContext(), textgenerationservice.BuildAssetCreationExtractionRequest(sanitizedText))
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
	return updated, translateAssetRepositoryError(err)
}

// DeleteAsset removes an asset owned by the authenticated user.
func (s *assetServiceImpl) DeleteAsset(ec *appcontext.GinContext, id string) (model.Asset, error) {
	userID, err := authenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset, err := s.assetRepository.DeleteForUser(ec, id, userID)
	return asset, translateAssetRepositoryError(err)
}
