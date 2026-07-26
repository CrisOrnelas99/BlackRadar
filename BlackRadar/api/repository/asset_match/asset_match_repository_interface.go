package repository

import (
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

type AssetMatchRepositoryInterface interface {
	FindByIDForUser(ec *appcontext.GinContext, id string, userID string) (model.Asset, error)
	UpdateMatchAnalysisForUser(ec *appcontext.GinContext, id string, userID string, analysis AssetMatchUpdate) (model.Asset, error)
}
