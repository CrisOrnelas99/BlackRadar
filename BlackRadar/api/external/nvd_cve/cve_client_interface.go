/*
Package cveclient interface defines the NVD CVE lookup contract consumed by
services that need backend-owned vulnerability enrichment.
*/
package cveclient

import "context"

type CVEClientInterface interface {
	/*
		LookupCVE retrieves one CVE record from NVD by normalized CVE ID and maps
		it into the safe backend DTO used by service logic.

		Implementations must honor ctx cancellation, validate the CVE identifier,
		apply outbound timeout/rate-limit/retry behavior, limit response bodies,
		and return sentinel errors such as ErrInvalidCVEID, ErrCVEIDNotFound,
		ErrNVDRateLimited, ErrNVDUnavailable, or ErrInvalidNVDResponse.

		Callers should pass only service-controlled CVE identifiers. Raw HTTP
		request bodies, Gin contexts, user credentials, and API keys should never
		cross this interface.
	*/
	LookupCVE(ctx context.Context, cveID string) (CVELookupResponse, error)

	/*
		SearchCVEsByCPE retrieves vulnerable CVE records for an exact NVD CPE 2.3
		name and returns a bounded list of safe backend DTOs.

		Implementations must honor ctx cancellation, validate that cpeName is an
		exact CPE value, bound the result limit, apply outbound timeout/rate-limit
		and retry behavior, and return sentinel errors such as ErrInvalidCPESearch,
		ErrNVDRateLimited, ErrNVDUnavailable, or ErrInvalidNVDResponse.
	*/
	SearchCVEsByCPE(ctx context.Context, cpeName string, limit int) ([]CVELookupResponse, error)

	/*
		SearchCVEsByKeyword retrieves CVE records for a bounded backend-generated
		NVD keyword search when exact CPE matching is not enough.

		Implementations must honor ctx cancellation, normalize and bound the
		keyword text, clamp the result limit, apply outbound timeout/rate-limit
		and retry behavior, and return sentinel errors such as ErrInvalidCVESearch,
		ErrNVDRateLimited, ErrNVDUnavailable, or ErrInvalidNVDResponse.
	*/
	SearchCVEsByKeyword(ctx context.Context, keywordSearch string, limit int) ([]CVELookupResponse, error)
}

var _ CVEClientInterface = (*Client)(nil)
