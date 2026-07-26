package cpeclient

import "context"

type CPEClientInterface interface {
	SearchCandidates(ctx context.Context, request CPEMatchRequest) ([]CPECandidate, error)
}

var _ CPEClientInterface = (*CPEClient)(nil)
