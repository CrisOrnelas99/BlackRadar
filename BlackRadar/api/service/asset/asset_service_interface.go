package service

import (
	"context"

	nvdcveclient "blackradar/api/external/nvd_cve"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
	promptservice "blackradar/api/service/prompt"
)

type AssetService interface {
	GetAllAssets(ec *appcontext.GinContext) ([]model.Asset, error)
	GetAsset(ec *appcontext.GinContext, id string) (model.Asset, error)
	CreateAsset(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error)
	CreateAssetFromAI(ec *appcontext.GinContext, rawText string) (model.Asset, error)
	UpdateAsset(ec *appcontext.GinContext, id string, asset model.Asset) (model.Asset, error)
	DeleteAsset(ec *appcontext.GinContext, id string) (model.Asset, error)
	AssignVulnerability(ec *appcontext.GinContext, assetID string, vulnerabilityID string) (model.Asset, error)
	AssignVulnerabilityByCVE(ec *appcontext.GinContext, assetID string, cveID string) (model.Asset, error)
	RemoveVulnerability(ec *appcontext.GinContext, assetID string, vulnerabilityID string) (model.Asset, error)
}

type nvdLookupService interface {
	LookupCVE(ec *appcontext.GinContext, cveID string) (nvdcveclient.CVELookupResponse, error)
}

type textGenerationService interface {
	GenerateText(ctx context.Context, request promptservice.TextGenerationRequest) (promptservice.TextGenerationResponse, error)
}
