package service

import (
	"fmt"
	"net"
	"strings"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/model"
	repository_assets "secureops/backend-go/api/repository"
)

type AssetService interface {
	GetAllAssets(ec *appcontext.EchoContext) ([]model.Asset, error)
	GetAsset(ec *appcontext.EchoContext, id int64) (model.Asset, error)
	CreateAsset(ec *appcontext.EchoContext, asset model.Asset) (model.Asset, error)
	UpdateAsset(ec *appcontext.EchoContext, id int64, asset model.Asset) (model.Asset, error)
	DeleteAsset(ec *appcontext.EchoContext, id int64) (model.Asset, error)
	AssignVulnerability(ec *appcontext.EchoContext, assetID int64, vulnerabilityID int64) (model.Asset, error)
	RemoveVulnerability(ec *appcontext.EchoContext, assetID int64, vulnerabilityID int64) (model.Asset, error)
	CalculateRisk(ec *appcontext.EchoContext, id int64) (model.Asset, error)
}

type assetServiceImpl struct {
	restClient *RestClient
}

var defaultRestClient *RestClient

func NewAssetService(restClient *RestClient) AssetService {
	defaultRestClient = restClient
	return &assetServiceImpl{restClient: restClient}
}

func GetAssetServiceFromEchoContext(ec *appcontext.EchoContext) AssetService {
	if ec != nil {
		if value, exists := ec.Get(appcontext.AssetServiceKey); exists {
			if service, ok := value.(AssetService); ok {
				return service
			}
		}

		assetService := &assetServiceImpl{restClient: defaultRestClient}
		ec.Set(appcontext.AssetServiceKey, assetService)
		return assetService
	}

	return &assetServiceImpl{restClient: defaultRestClient}
}

func (s *assetServiceImpl) GetAllAssets(ec *appcontext.EchoContext) ([]model.Asset, error) {
	assetRepository := repository_assets.GetAssetRepoFromEchoContext(ec)
	assets, err := assetRepository.FindAll(ec)
	return assets, s.translateRepositoryError(err)
}

func (s *assetServiceImpl) GetAsset(ec *appcontext.EchoContext, id int64) (model.Asset, error) {
	assetRepository := repository_assets.GetAssetRepoFromEchoContext(ec)
	asset, err := assetRepository.FindByID(ec, id)
	return asset, s.translateRepositoryError(err)
}

func (s *assetServiceImpl) CreateAsset(ec *appcontext.EchoContext, asset model.Asset) (model.Asset, error) {
	if err := validateAsset(asset); err != nil {
		return model.Asset{}, err
	}
	assetRepository := repository_assets.GetAssetRepoFromEchoContext(ec)
	created, err := assetRepository.Save(ec, asset)
	return created, s.translateRepositoryError(err)
}

func (s *assetServiceImpl) UpdateAsset(ec *appcontext.EchoContext, id int64, asset model.Asset) (model.Asset, error) {
	if err := validateAsset(asset); err != nil {
		return model.Asset{}, err
	}
	assetRepository := repository_assets.GetAssetRepoFromEchoContext(ec)
	if _, err := assetRepository.FindByID(ec, id); err != nil {
		return model.Asset{}, s.translateRepositoryError(err)
	}
	updated, err := assetRepository.Update(ec, id, asset)
	return updated, s.translateRepositoryError(err)
}

func (s *assetServiceImpl) DeleteAsset(ec *appcontext.EchoContext, id int64) (model.Asset, error) {
	assetRepository := repository_assets.GetAssetRepoFromEchoContext(ec)
	if _, err := assetRepository.FindByID(ec, id); err != nil {
		return model.Asset{}, s.translateRepositoryError(err)
	}
	asset, err := assetRepository.Delete(ec, id)
	return asset, s.translateRepositoryError(err)
}

func (s *assetServiceImpl) AssignVulnerability(ec *appcontext.EchoContext, assetID int64, vulnerabilityID int64) (model.Asset, error) {
	assetRepository := repository_assets.GetAssetRepoFromEchoContext(ec)
	if err := assetRepository.EnsureAssetAndVulnerability(ec, assetID, vulnerabilityID); err != nil {
		return model.Asset{}, s.translateRepositoryError(err)
	}
	asset, err := assetRepository.AssignVulnerability(ec, assetID, vulnerabilityID)
	return asset, s.translateRepositoryError(err)
}

func (s *assetServiceImpl) RemoveVulnerability(ec *appcontext.EchoContext, assetID int64, vulnerabilityID int64) (model.Asset, error) {
	assetRepository := repository_assets.GetAssetRepoFromEchoContext(ec)
	if err := assetRepository.EnsureAssetAndVulnerability(ec, assetID, vulnerabilityID); err != nil {
		return model.Asset{}, s.translateRepositoryError(err)
	}
	asset, err := assetRepository.RemoveVulnerability(ec, assetID, vulnerabilityID)
	return asset, s.translateRepositoryError(err)
}

func (s *assetServiceImpl) CalculateRisk(ec *appcontext.EchoContext, id int64) (model.Asset, error) {
	assetRiskService := GetAssetRiskServiceFromEchoContext(ec)
	request, err := assetRiskService.LoadRiskCalculationRequest(ec, id)
	if err != nil {
		return model.Asset{}, err
	}

	if s.restClient == nil {
		return model.Asset{}, fmt.Errorf("%w: missing risk service client", ErrRemoteService)
	}

	response, err := s.restClient.CalculateRisk(ec.RequestContext(), request)
	if err != nil {
		return model.Asset{}, fmt.Errorf("%w: %w", ErrRemoteService, err)
	}

	asset, err := assetRiskService.PersistRiskResult(ec, id, response)
	return asset, err
}

func (s *assetServiceImpl) translateRepositoryError(err error) error {
	return translateRepositoryError(err)
}

func validateAsset(asset model.Asset) error {
	if strings.TrimSpace(asset.Name) == "" ||
		strings.TrimSpace(asset.Type) == "" ||
		strings.TrimSpace(asset.Owner) == "" ||
		strings.TrimSpace(asset.Criticality) == "" {
		return ErrInvalidRequestData
	}

	if ip := net.ParseIP(asset.IPAddress); ip == nil || ip.To4() == nil {
		return ErrInvalidRequestData
	}

	return nil
}
