/*
Package service defines asset-risk calculation and persistence workflows.
*/
package service

import (
	"context"

	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

type AssetRiskService interface {
	/*
		RefreshAssetRisk recalculates and persists the derived risk level for one
		asset owned by the authenticated user.

		The implementation must read the user ID from ec rather than from a
		request payload, load only active asset-vulnerability relationships, and
		ensure the asset and its vulnerabilities are scoped to that user. The
		calculated value is nil when the asset has no active vulnerabilities.

		When ec contains a request-scoped transaction database, all reads and the
		risk-level update must use that database. This allows assignment and
		removal workflows to commit the relationship and derived risk state
		atomically. Repository failures must be translated into asset-risk
		service error categories.
	*/
	RefreshAssetRisk(ec *appcontext.GinContext, assetID string) error

	/*
		RefreshRisksForVulnerability recalculates every active, user-owned asset
		relationship for vulnerabilityID.

		This is used when a vulnerability's severity or active state changes.
		Implementations must find the affected assets from active bridge rows,
		recalculate each asset from its complete active vulnerability set, and
		use the request-scoped transaction when one is present. A vulnerability
		that is not assigned to an asset must not cause an asset update.
	*/
	RefreshRisksForVulnerability(ec *appcontext.GinContext, vulnerabilityID string) error

	/*
		BackfillAssetRiskLevels recalculates stored risk levels for every asset.

		This is a startup maintenance operation for existing rows. It must remain
		backend-owned, use the repository's database transaction, include only
		active relationships, and fail without partially committing a backfill.
		The operation updates derived risk state; it does not change ownership,
		asset fields, vulnerability records, or CPE matching metadata.
	*/
	BackfillAssetRiskLevels(ctx context.Context) error

	/*
		CalculateRiskLevel returns the derived asset risk level for the supplied
		active vulnerability set.

		The current rule normalizes severity case and whitespace, chooses the
		highest value using Low < Medium < High < Critical, maps unknown severity
		values to Low, and returns nil when the set is empty. The function is
		deterministic and must not perform database, HTTP, logging, or request
		context work.
	*/
	CalculateRiskLevel(vulnerabilities []model.Vulnerability) *string
}
