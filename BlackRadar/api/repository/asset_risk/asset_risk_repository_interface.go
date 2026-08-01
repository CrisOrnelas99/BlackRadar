/*
Package repository defines asset-risk persistence contracts consumed by the
asset-risk service.
*/
package repository

import (
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

type AssetRiskRepositoryInterface interface {
	/*
		FindActiveVulnerabilitiesForUser loads the active vulnerabilities assigned
		to assetID for userID.

		Implementations must join through asset_vulnerabilities with
		deleted_at IS NULL, scope both the asset and vulnerability ownership to
		userID, and return persistence-category errors without exposing raw SQL
		details as a domain result. The request-scoped database must be preferred
		when ec contains a transaction.
	*/
	FindActiveVulnerabilitiesForUser(ec *appcontext.GinContext, assetID string, userID string) ([]model.Vulnerability, error)

	/*
		FindAssignedAssetIDsForVulnerability returns asset IDs owned by userID
		that have an active relationship to vulnerabilityID.

		Implementations must exclude soft-deleted bridge rows, filter the asset
		owner by userID, and return deterministic identifiers suitable for
		refreshing each affected asset. This method reads relationship state only;
		it must not calculate or update risk.
	*/
	FindAssignedAssetIDsForVulnerability(ec *appcontext.GinContext, vulnerabilityID string, userID string) ([]string, error)

	/*
		UpdateRiskLevelForUser persists the already-calculated risk level for an
		asset owned by userID.

		The repository must not decide how severity maps to risk. It must apply
		the supplied value with an ownership predicate, use the request-scoped
		database when present, and return ErrRecordNotFound when no owned asset
		was updated. A nil risk level represents an asset with no active assigned
		vulnerabilities.
	*/
	UpdateRiskLevelForUser(ec *appcontext.GinContext, assetID string, userID string, riskLevel *string) error
}
