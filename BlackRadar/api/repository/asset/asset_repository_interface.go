/*
Package repository interface defines the asset persistence contract consumed by
asset services.
*/
package repository

import (
	"blackradar/api/common/pagination"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

type AssetRepositoryInterface interface {
	// FindByUser returns one filtered and ordered page of active assets owned by userID.
	FindByUser(ec *appcontext.GinContext, userID string, query model.AssetListQuery) (pagination.Page[model.Asset], error)

	// SummarizeByUser returns dashboard aggregate counts for active assets owned by userID.
	SummarizeByUser(ec *appcontext.GinContext, userID string) (model.AssetSummary, error)

	/*
		FindByIDForUser returns one active asset matching id and userID.

		Implementations must require both identifiers in the lookup and return
		ErrRecordNotFound when the asset does not exist or is not owned by userID.
	*/
	FindByIDForUser(ec *appcontext.GinContext, id string, userID string) (model.Asset, error)

	/*
		FindVulnerabilitiesForAsset returns active vulnerabilities attached to
		an asset owned by userID.

		Implementations must scope both the asset and vulnerability records to
		userID and exclude soft-deleted assignments.
	*/
	FindVulnerabilitiesForAsset(ec *appcontext.GinContext, assetID string, userID string) ([]model.Vulnerability, error)

	/*
		ExistsBySignatureForUser reports whether userID already owns an asset with
		the same normalized identifying fields.

		This supports service-level duplicate checks; it should not decide business
		meaning beyond database existence.
	*/
	ExistsBySignatureForUser(ec *appcontext.GinContext, asset model.Asset, userID string) (bool, error)

	/*
		CreateForUser persists a new asset owned by userID and returns the created
		row with generated identifiers.

		Implementations should enforce persistence constraints, set ownership at
		the database boundary, and return repository sentinel errors for duplicate,
		foreign-key, check-constraint, or persistence failures.
	*/
	CreateForUser(ec *appcontext.GinContext, userID string, asset model.Asset) (model.Asset, error)

	/*
		UpdateForUser applies asset updates to the row matching id and userID and
		returns the updated asset.

		Implementations must scope by both id and userID, preserve ownership, and
		return ErrRecordNotFound when no owned asset matches.
	*/
	UpdateForUser(ec *appcontext.GinContext, id string, userID string, asset model.Asset) (model.Asset, error)

	/*
		DeleteForUser removes the asset matching id and userID and returns the
		deleted asset state.

		Implementations must scope by both id and userID, keep related persistence
		cleanup atomic when applicable, and return ErrRecordNotFound when no owned
		asset matches.
	*/
	DeleteForUser(ec *appcontext.GinContext, id string, userID string) (model.Asset, error)
}
