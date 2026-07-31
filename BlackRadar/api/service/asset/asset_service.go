// Package service provides asset-related application services.
package service

import (
	"fmt"

	openaiexternal "blackradar/api/external/openai"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
	assetrepository "blackradar/api/repository/asset"
	auditservice "blackradar/api/service/audit"
	textgenerationservice "blackradar/api/service/text_generation"
)

// assetServiceImpl implements asset business workflows.
type assetServiceImpl struct {
	assetRepository assetrepository.AssetRepositoryInterface
	textAI          openaiexternal.OpenAIClientInterface
	textGeneration  textgenerationservice.TextGenerationService
	auditService    auditservice.Service
}

// NewAssetService creates an asset service backed by the supplied repository.
func NewAssetService(assetRepository assetrepository.AssetRepositoryInterface, textAI openaiexternal.OpenAIClientInterface, auditServices ...auditservice.Service) *assetServiceImpl {
	service := &assetServiceImpl{
		assetRepository: assetRepository,
		textAI:          textAI,
		textGeneration:  textgenerationservice.NewTextGenerationService(),
	}
	if len(auditServices) > 0 {
		service.auditService = auditServices[0]
	}
	return service
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

// CreateAsset validates and creates a new asset for the authenticated user.
func (s *assetServiceImpl) CreateAsset(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error) {
	return s.createAsset(ec, asset, "asset.create")
}

func (s *assetServiceImpl) createAsset(ec *appcontext.GinContext, asset model.Asset, action string) (model.Asset, error) {
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

	if s.auditService == nil {
		created, err := s.assetRepository.CreateForUser(ec, userID, asset)
		return created, translateAssetRepositoryError(err)
	}
	var created model.Asset
	err = runAssetAuditTransaction(ec, func(txContext *appcontext.GinContext) error {
		var createErr error
		created, createErr = s.assetRepository.CreateForUser(txContext, userID, asset)
		if createErr != nil {
			return translateAssetRepositoryError(createErr)
		}
		return s.auditService.Record(txContext, auditservice.EventInput{ActorUserID: &userID, Action: action, ResourceType: "asset", ResourceID: &created.ID, Result: auditservice.ResultSucceeded})
	})
	return created, err
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

	response, err := s.textAI.GenerateText(ec.RequestContext(), s.textGeneration.BuildAssetCreationExtractionRequest(sanitizedText))
	if err != nil {
		return model.Asset{}, fmt.Errorf("%w: asset AI extraction failed: %w", ErrAssetExternalService, err)
	}

	asset, err := assetFromAIExtraction(response.Text)
	if err != nil {
		return model.Asset{}, err
	}

	return s.createAsset(ec, asset, "asset.create.ai_persisted")
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

	if s.auditService == nil {
		updated, err := s.assetRepository.UpdateForUser(ec, id, userID, asset)
		return updated, translateAssetRepositoryError(err)
	}
	var updated model.Asset
	err = runAssetAuditTransaction(ec, func(txContext *appcontext.GinContext) error {
		var updateErr error
		updated, updateErr = s.assetRepository.UpdateForUser(txContext, id, userID, asset)
		if updateErr != nil {
			return translateAssetRepositoryError(updateErr)
		}
		return s.auditService.Record(txContext, auditservice.EventInput{ActorUserID: &userID, Action: "asset.update", ResourceType: "asset", ResourceID: &updated.ID, Result: auditservice.ResultSucceeded})
	})
	return updated, err
}

// DeleteAsset removes an asset owned by the authenticated user.
func (s *assetServiceImpl) DeleteAsset(ec *appcontext.GinContext, id string) (model.Asset, error) {
	userID, err := authenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	if s.auditService == nil {
		asset, err := s.assetRepository.DeleteForUser(ec, id, userID)
		return asset, translateAssetRepositoryError(err)
	}
	var deleted model.Asset
	err = runAssetAuditTransaction(ec, func(txContext *appcontext.GinContext) error {
		var deleteErr error
		deleted, deleteErr = s.assetRepository.DeleteForUser(txContext, id, userID)
		if deleteErr != nil {
			return translateAssetRepositoryError(deleteErr)
		}
		return s.auditService.Record(txContext, auditservice.EventInput{ActorUserID: &userID, Action: "asset.delete", ResourceType: "asset", ResourceID: &deleted.ID, Result: auditservice.ResultSucceeded})
	})
	return deleted, err
}
