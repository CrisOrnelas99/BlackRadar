/*
Package cpeclient interface defines the NVD CPE lookup contract consumed by
services that need backend-owned product matching.
*/
package cpeclient

import "context"

type CPEClientInterface interface {
	/*
		SearchCandidates searches NVD CPE records with one normalized,
		backend-generated exact component match or keyword request and returns
		bounded CPE candidates for service-side matching.

		Implementations must honor ctx cancellation, validate and bound the
		search, apply outbound timeout/rate-limit behavior, limit response
		bodies, and return sentinel errors such as ErrInvalidCPESearch,
		ErrNVDRateLimited, ErrNVDUnavailable, or ErrInvalidNVDResponse.

		Callers should pass only service-generated CPEMatchRequest values. Raw
		HTTP request bodies, Gin contexts, user credentials, and API keys should
		never cross this interface.
	*/
	SearchCandidates(ctx context.Context, request CPEMatchRequest) ([]CPECandidate, error)
}

var _ CPEClientInterface = (*CPEClient)(nil)
