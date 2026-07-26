package asset_match

import (
	"context"

	nvdcpeclient "blackradar/api/external/nvd_cpe"
	nvdcveclient "blackradar/api/external/nvd_cve"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
	textgenerationservice "blackradar/api/service/text_generation"
)

type AssetMatchService interface {
	AnalyzeAndPersistAssetMatch(ec *appcontext.GinContext, assetID string) (model.Asset, error)
	AnalyzePersistAndAttachVulnerabilities(ec *appcontext.GinContext, assetID string) (model.Asset, error)
}

type NVDLookupService interface {
	LookupCVE(ec *appcontext.GinContext, cveID string) (nvdcveclient.CVELookupResponse, error)
}

type textGenerationService interface {
	GenerateText(ctx context.Context, request textgenerationservice.TextGenerationRequest) (textgenerationservice.TextGenerationResponse, error)
}

// CPECandidateSearcher looks up NVD CPE candidates for a normalized search request.
type CPECandidateSearcher interface {
	SearchCandidates(ctx context.Context, request nvdcpeclient.CPEMatchRequest) ([]nvdcpeclient.CPECandidate, error)
}

// CVEByCPESearcher looks up NVD CVEs for selected CPEs and bounded keyword fallback searches.
type CVEByCPESearcher interface {
	SearchCVEsByCPE(ctx context.Context, cpeName string, limit int) ([]nvdcveclient.CVELookupResponse, error)
	SearchCVEsByKeyword(ctx context.Context, keywordSearch string, limit int) ([]nvdcveclient.CVELookupResponse, error)
}

type cveLookupClient interface {
	LookupCVE(ctx context.Context, cveID string) (nvdcveclient.CVELookupResponse, error)
}
