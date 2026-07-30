/*
Package asset_match interface defines asset matching service contracts consumed
by controllers.
*/
package asset_match

import (
	nvdcveclient "blackradar/api/external/nvd_cve"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

type AssetMatchService interface {
	/*
		PreviewAssetMatch analyzes one authenticated user's asset and returns a
		non-persistent CPE proposal.

		Implementations must enforce asset ownership and must not persist asset,
		vulnerability, assignment, or risk changes from the AI analysis.
	*/
	PreviewAssetMatch(ec *appcontext.GinContext, assetID string) (AssetMatchAnalysis, error)

	/*
		ApplyApprovedCPEMatch attaches NVD vulnerabilities for an administrator-
		selected CPE and refreshes the affected asset's risk.

		Implementations must enforce authorization and ownership, validate the
		selected CPE through NVD before persistence, and keep all writes atomic.
	*/
	ApplyApprovedCPEMatch(ec *appcontext.GinContext, assetID string, selectedCPE string) (model.Asset, error)
}

/*
NVDLookupService describes CVE lookup operations exposed to controllers.
*/
type NVDLookupService interface {
	/*
		LookupCVE returns provider-backed CVE details for cveID.

		Implementations should validate the CVE identifier, call the NVD client,
		and translate missing, malformed, rate-limited, or unavailable provider
		responses into service-layer errors.
	*/
	LookupCVE(ec *appcontext.GinContext, cveID string) (nvdcveclient.CVELookupResponse, error)
}
