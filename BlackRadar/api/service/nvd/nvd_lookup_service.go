// Package service provides NVD lookup application services.
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"blackradar/api/controller/dto"
	baseexternal "blackradar/api/external"
	appcontext "blackradar/api/requestContext"
	baseservice "blackradar/api/service"
)

type cveLookupClient interface {
	LookupCVE(ctx context.Context, cveID string) (dto.CVELookupResponse, error)
}

type nvdLookupServiceImpl struct {
	client cveLookupClient
}

// NewNVDLookupService creates a read-only NVD lookup service.
func NewNVDLookupService(client cveLookupClient) baseservice.NVDLookupService {
	return &nvdLookupServiceImpl{client: client}
}

// LookupCVE validates the request and returns official NVD details for one CVE ID.
func (s *nvdLookupServiceImpl) LookupCVE(ec *appcontext.GinContext, cveID string) (dto.CVELookupResponse, error) {
	if _, err := baseservice.AuthenticatedUserID(ec); err != nil {
		return dto.CVELookupResponse{}, err
	}

	normalizedCVEID := baseservice.NormalizeCVEID(cveID)
	if err := baseservice.ValidateCVEID(normalizedCVEID); err != nil {
		return dto.CVELookupResponse{}, err
	}

	ctx, cancel := context.WithTimeout(ec.Request.Context(), 10*time.Second)
	defer cancel()

	response, err := s.client.LookupCVE(ctx, normalizedCVEID)
	if err != nil {
		return dto.CVELookupResponse{}, translateNVDError(err)
	}
	return response, nil
}

func translateNVDError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, baseexternal.ErrInvalidCVEID):
		return fmt.Errorf("%w: %w", baseservice.ErrInvalidRequestData, err)
	case errors.Is(err, baseexternal.ErrCVEIDNotFound):
		return fmt.Errorf("%w: %w", baseservice.ErrNotFound, err)
	case errors.Is(err, baseexternal.ErrNVDRateLimited):
		return fmt.Errorf("%w: %w", baseservice.ErrRateLimited, err)
	case errors.Is(err, baseexternal.ErrNVDUnavailable), errors.Is(err, baseexternal.ErrInvalidNVDResponse):
		return fmt.Errorf("%w: %w", baseservice.ErrExternalService, err)
	default:
		return fmt.Errorf("%w: %v", baseservice.ErrExternalService, err)
	}
}
