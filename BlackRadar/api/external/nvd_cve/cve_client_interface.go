package cveclient

import "context"

type CVEClientInterface interface {
	LookupCVE(ctx context.Context, cveID string) (CVELookupResponse, error)
	SearchCVEsByCPE(ctx context.Context, cpeName string, limit int) ([]CVELookupResponse, error)
	SearchCVEsByKeyword(ctx context.Context, keywordSearch string, limit int) ([]CVELookupResponse, error)
}

var _ CVEClientInterface = (*Client)(nil)
