package repository

import (
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

type AssetRepositoryInterface interface {
	FindAllByUser(ec *appcontext.GinContext, userID string) ([]model.Asset, error)
	FindByIDForUser(ec *appcontext.GinContext, id string, userID string) (model.Asset, error)
	ExistsBySignatureForUser(ec *appcontext.GinContext, asset model.Asset, userID string) (bool, error)
	Save(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error)
	UpdateForUser(ec *appcontext.GinContext, id string, userID string, asset model.Asset) (model.Asset, error)
	DeleteForUser(ec *appcontext.GinContext, id string, userID string) (model.Asset, error)
	UpdateMatchAnalysisForUser(ec *appcontext.GinContext, id string, userID string, analysis any) (model.Asset, error)
	AssignVulnerabilityForUser(ec *appcontext.GinContext, assetID string, userID string, vulnerabilityID string) (model.Asset, error)
	RemoveVulnerabilityForUser(ec *appcontext.GinContext, assetID string, userID string, vulnerabilityID string) (model.Asset, error)
}
