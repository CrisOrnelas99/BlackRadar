/*
Package repository interface defines the asset match persistence contract
consumed by asset matching services.
*/
package repository

import (
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

type AssetMatchRepositoryInterface interface {
	/*
		FindByIDForUser returns one active asset matching id and userID with the
		state needed for matching.

		Implementations must scope by both identifiers and return ErrRecordNotFound
		when the asset does not exist or is not owned by userID.
	*/
	FindByIDForUser(ec *appcontext.GinContext, id string, userID string) (model.Asset, error)

	/*
		UpdateMatchAnalysisForUser stores backend-generated CPE match metadata for
		the asset matching id and userID.

		Implementations must scope by both identifiers, preserve wrapped database
		causes, and return repository sentinel errors for missing rows or
		persistence failures.
	*/
	UpdateMatchAnalysisForUser(ec *appcontext.GinContext, id string, userID string, analysis AssetMatchUpdate) (model.Asset, error)
}
