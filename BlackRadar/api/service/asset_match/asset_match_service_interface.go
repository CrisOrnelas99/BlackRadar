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
		AnalyzeAndPersistAssetMatch analyzes one authenticated user's asset and
		stores the selected CPE match metadata.

		Implementations should validate the asset id, enforce user ownership,
		call the text-generation and NVD dependencies needed for matching, and
		translate repository or external failures into service-layer errors.
	*/
	AnalyzeAndPersistAssetMatch(ec *appcontext.GinContext, assetID string) (model.Asset, error)

	/*
		AnalyzePersistAndAttachVulnerabilities analyzes one authenticated user's
		asset, persists CPE match metadata, and attaches matching CVEs.

		Implementations should keep the matching and relationship updates
		consistent through the repository layer, enforce ownership, and return
		service dependency, validation, not-found, or conflict errors when the
		workflow cannot complete.
	*/
	AnalyzePersistAndAttachVulnerabilities(ec *appcontext.GinContext, assetID string) (model.Asset, error)
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
