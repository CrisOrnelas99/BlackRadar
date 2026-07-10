// Package service provides NVD lookup application services.
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	appcontext "blackradar/api/context"
	"blackradar/api/dto"
	nvdexternal "blackradar/api/external/nvd"
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
	case errors.Is(err, nvdexternal.ErrInvalidCVEID):
		return fmt.Errorf("%w: %w", baseservice.ErrInvalidRequestData, err)
	case errors.Is(err, nvdexternal.ErrCVEIDNotFound):
		return fmt.Errorf("%w: %w", baseservice.ErrNotFound, err)
	case errors.Is(err, nvdexternal.ErrNVDRateLimited):
		return fmt.Errorf("%w: %w", baseservice.ErrRateLimited, err)
	case errors.Is(err, nvdexternal.ErrNVDUnavailable), errors.Is(err, nvdexternal.ErrInvalidNVDResponse):
		return fmt.Errorf("%w: %w", baseservice.ErrExternalService, err)
	default:
		return fmt.Errorf("%w: %v", baseservice.ErrExternalService, err)
	}
}
