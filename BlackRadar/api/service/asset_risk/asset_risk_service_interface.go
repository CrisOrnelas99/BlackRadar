/*
Package service defines asset-risk calculation and persistence workflows.
*/
package service

import (
	appcontext "blackradar/api/platform/requestcontext"
)

type AssetRiskService interface {
	/*
		RefreshAssetRisk recalculates and persists the derived risk level for one
		asset in the authenticated user's organization.

		The implementation must read the user ID from ec rather than from a
		request payload, load only active asset-vulnerability relationships, and
		ensure the asset and its vulnerabilities are scoped to that user. The
		calculated value uses Low as the vulnerability baseline when the asset
		has no active vulnerabilities.

		When ec contains a request-scoped transaction database, all reads and the
		risk-level update must use that database. This allows assignment and
		removal workflows to commit the relationship and derived risk state
		atomically. Repository failures must be translated into asset-risk
		service error categories.
	*/
	RefreshAssetRisk(ec *appcontext.GinContext, assetID string) error

	/*
		RefreshRisksForVulnerability recalculates every active, organization-scoped asset
		relationship for vulnerabilityID.

		This is used when a vulnerability's severity or active state changes.
		Implementations must find the affected assets from active bridge rows,
		recalculate each asset from its complete active vulnerability set, and
		use the request-scoped transaction when one is present. A vulnerability
		that is not assigned to an asset must not cause an asset update.
	*/
	RefreshRisksForVulnerability(ec *appcontext.GinContext, vulnerabilityID string) error
}
