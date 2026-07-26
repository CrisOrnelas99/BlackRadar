package controller

import (
	"errors"
	"net/http"

	shared "blackradar/api/controller/shared"
	appcontext "blackradar/api/platform/requestcontext"
	assetservice "blackradar/api/service/asset"
	assetvulnerabilityservice "blackradar/api/service/asset_vulnerability"
	matchservice "blackradar/api/service/match"
)

// handleAssetServiceError maps service error categories to HTTP responses.
func handleAssetServiceError(ec *appcontext.GinContext, err error) bool {
	var validationErr *assetservice.ValidationError
	var conflictErr *assetservice.ConflictError
	var forbiddenErr *assetservice.ForbiddenError
	var notFoundErr *assetservice.NotFoundError
	var assetDependencyErr *assetservice.DependencyError
	var assetVulnerabilityValidationErr *assetvulnerabilityservice.ValidationError
	var assetVulnerabilityConflictErr *assetvulnerabilityservice.ConflictError
	var assetVulnerabilityForbiddenErr *assetvulnerabilityservice.ForbiddenError
	var assetVulnerabilityNotFoundErr *assetvulnerabilityservice.NotFoundError
	var assetVulnerabilityDependencyErr *assetvulnerabilityservice.DependencyError
	var assetVulnerabilityInternalErr *assetvulnerabilityservice.InternalError
	var matchDependencyErr *matchservice.DependencyError
	var assetInternalErr *assetservice.InternalError
	var matchInternalErr *matchservice.InternalError

	switch {
	case errors.As(err, &validationErr), errors.As(err, &assetVulnerabilityValidationErr):
		return shared.HandleError(ec, http.StatusBadRequest, err, err.Error())
	case errors.As(err, &conflictErr), errors.As(err, &assetVulnerabilityConflictErr):
		return shared.HandleError(ec, http.StatusConflict, err, err.Error())
	case errors.As(err, &forbiddenErr), errors.As(err, &assetVulnerabilityForbiddenErr):
		return shared.HandleError(ec, http.StatusForbidden, err, err.Error())
	case errors.As(err, &notFoundErr), errors.As(err, &assetVulnerabilityNotFoundErr):
		return shared.HandleError(ec, http.StatusNotFound, err, err.Error())
	case errors.As(err, &assetDependencyErr), errors.As(err, &assetVulnerabilityDependencyErr), errors.As(err, &matchDependencyErr):
		return shared.HandleError(ec, http.StatusBadGateway, err, "Asset dependency unavailable")
	case errors.As(err, &assetInternalErr), errors.As(err, &assetVulnerabilityInternalErr), errors.As(err, &matchInternalErr):
		return shared.HandleError(ec, http.StatusInternalServerError, err, "Asset service failed")
	}

	return false
}
