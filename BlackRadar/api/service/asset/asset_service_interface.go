/*
Package service interface defines the asset service contract consumed by
controllers.
*/
package service

import (
	"blackradar/api/common/pagination"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

type AssetService interface {
	// GetAssetPage returns one validated, bounded page of assets owned by the authenticated user.
	GetAssetPage(ec *appcontext.GinContext, query model.AssetListQuery) (pagination.Page[model.Asset], error)

	// GetAssetSummary returns dashboard aggregate counts for the authenticated user's assets.
	GetAssetSummary(ec *appcontext.GinContext) (model.AssetSummary, error)

	/*
		GetAsset returns one asset owned by the authenticated user.

		Implementations should validate the asset identifier, enforce ownership
		through the repository lookup, and translate missing records into a
		service not-found error.
	*/
	GetAsset(ec *appcontext.GinContext, id string) (model.Asset, error)

	/*
		GetAssetVulnerabilities returns active vulnerabilities attached to an
		asset owned by the authenticated user.

		Implementations must verify asset ownership and return only active,
		user-scoped vulnerability assignments.
	*/
	GetAssetVulnerabilities(ec *appcontext.GinContext, id string) ([]model.Vulnerability, error)

	/*
		CreateAsset validates and creates a user-owned asset.

		Implementations should apply asset business validation, check for
		duplicates through the repository, and translate conflicts,
		validation failures, and dependency failures into service errors.
	*/
	CreateAsset(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error)

	/*
		UpdateAsset validates and updates an asset owned by the authenticated
		user.

		Implementations should validate the target id and update payload, enforce
		ownership through repository operations, and return service not-found,
		validation, conflict, or dependency errors as appropriate.
	*/
	UpdateAsset(ec *appcontext.GinContext, id string, asset model.Asset) (model.Asset, error)

	/*
		DeleteAsset removes an asset owned by the authenticated user.

		Implementations should validate the asset id, enforce ownership through
		the repository, and translate missing records or persistence failures into
		service-layer errors.
	*/
	DeleteAsset(ec *appcontext.GinContext, id string) (model.Asset, error)
}
