// Package match provides NVD lookup services used by asset matching workflows.
package match

import (
	"context"
	"errors"
	"fmt"
	"time"

	"blackradar/api/controller/dto"
	nvdcveclient "blackradar/api/external/nvd_cve"
	appcontext "blackradar/api/platform/requestcontext"
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
	if _, err := authenticatedUserID(ec); err != nil {
		return dto.CVELookupResponse{}, err
	}

	normalizedCVEID := normalizeCVEID(cveID)
	if err := validateCVEID(normalizedCVEID); err != nil {
		return dto.CVELookupResponse{}, ErrInvalidCVEID
	}
	if s.client == nil {
		return dto.CVELookupResponse{}, ErrMatchExternalService
	}

	ctx, cancel := context.WithTimeout(ec.Request.Context(), 10*time.Second)
	defer cancel()

	response, err := s.client.LookupCVE(ctx, normalizedCVEID)
	switch {
	case err == nil:
		return response, nil
	case errors.Is(err, nvdcveclient.ErrInvalidCVEID):
		return dto.CVELookupResponse{}, fmt.Errorf("%w: %w", ErrInvalidCVEID, err)
	case errors.Is(err, nvdcveclient.ErrCVEIDNotFound):
		return dto.CVELookupResponse{}, fmt.Errorf("%w: %w", ErrCVENotFound, err)
	case errors.Is(err, nvdcveclient.ErrNVDRateLimited):
		return dto.CVELookupResponse{}, fmt.Errorf("%w: %w", ErrNVDLookupRateLimited, err)
	case errors.Is(err, nvdcveclient.ErrNVDUnavailable), errors.Is(err, nvdcveclient.ErrInvalidNVDResponse):
		return dto.CVELookupResponse{}, fmt.Errorf("%w: %w", ErrMatchExternalService, err)
	default:
		return dto.CVELookupResponse{}, fmt.Errorf("%w: %v", ErrMatchExternalService, err)
	}
}
