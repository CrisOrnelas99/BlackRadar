package asset_match

import (
	nvdcveclient "blackradar/api/external/nvd_cve"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

type AssetMatchService interface {
	AnalyzeAndPersistAssetMatch(ec *appcontext.GinContext, assetID string) (model.Asset, error)
	AnalyzePersistAndAttachVulnerabilities(ec *appcontext.GinContext, assetID string) (model.Asset, error)
}

type NVDLookupService interface {
	LookupCVE(ec *appcontext.GinContext, cveID string) (nvdcveclient.CVELookupResponse, error)
}
