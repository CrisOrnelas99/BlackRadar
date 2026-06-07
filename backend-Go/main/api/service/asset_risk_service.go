package service

import (
	"strings"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/model"
	repository_assets "secureops/backend-go/api/repository"
)

type AssetRiskService interface {
	LoadRiskCalculationRequest(ec *appcontext.EchoContext, id int64) (model.RiskCalculationRequest, error)
	PersistRiskResult(ec *appcontext.EchoContext, id int64, response model.RiskCalculationResponse) (model.Asset, error)
}

type assetRiskServiceImpl struct{}

func NewAssetRiskService() AssetRiskService {
	return &assetRiskServiceImpl{}
}

func GetAssetRiskServiceFromEchoContext(ec *appcontext.EchoContext) AssetRiskService {
	if ec != nil {
		if value, exists := ec.Get(appcontext.AssetRiskServiceKey); exists {
			if service, ok := value.(AssetRiskService); ok {
				return service
			}
		}

		assetRiskService := &assetRiskServiceImpl{}
		ec.Set(appcontext.AssetRiskServiceKey, assetRiskService)
		return assetRiskService
	}

	return &assetRiskServiceImpl{}
}

func (s *assetRiskServiceImpl) LoadRiskCalculationRequest(ec *appcontext.EchoContext, id int64) (model.RiskCalculationRequest, error) {
	assetRepository := repository_assets.GetAssetRepoFromEchoContext(ec)
	asset, err := assetRepository.FindByID(ec, id)
	if err != nil {
		return model.RiskCalculationRequest{}, s.translateRepositoryError(err)
	}

	return buildRiskCalculationRequest(asset), nil
}

func (s *assetRiskServiceImpl) PersistRiskResult(ec *appcontext.EchoContext, id int64, response model.RiskCalculationResponse) (model.Asset, error) {
	assetRepository := repository_assets.GetAssetRepoFromEchoContext(ec)
	asset, err := assetRepository.PersistRiskResult(ec, id, response)
	return asset, s.translateRepositoryError(err)
}

func buildRiskCalculationRequest(asset model.Asset) model.RiskCalculationRequest {
	request := model.RiskCalculationRequest{
		AssetID:     asset.ID,
		Criticality: asset.Criticality,
	}

	for _, vulnerability := range asset.Vulnerabilities {
		switch strings.ToLower(strings.TrimSpace(vulnerability.Severity)) {
		case "critical":
			request.CriticalVulnerabilities++
		case "high":
			request.HighVulnerabilities++
		case "medium":
			request.MediumVulnerabilities++
		case "low":
			request.LowVulnerabilities++
		}
	}

	return request
}

func (s *assetRiskServiceImpl) translateRepositoryError(err error) error {
	return translateRepositoryError(err)
}
