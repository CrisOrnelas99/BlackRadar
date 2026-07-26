package service

import (
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

type AssetService interface {
	GetAllAssets(ec *appcontext.GinContext) ([]model.Asset, error)
	GetAsset(ec *appcontext.GinContext, id string) (model.Asset, error)
	CreateAsset(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error)
	CreateAssetFromAI(ec *appcontext.GinContext, rawText string) (model.Asset, error)
	UpdateAsset(ec *appcontext.GinContext, id string, asset model.Asset) (model.Asset, error)
	DeleteAsset(ec *appcontext.GinContext, id string) (model.Asset, error)
}
