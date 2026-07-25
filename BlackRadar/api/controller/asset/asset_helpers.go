package controller

import (
	"errors"
	"net/http"

	shared "blackradar/api/controller/shared"
	appcontext "blackradar/api/platform/requestcontext"
	assetservice "blackradar/api/service/asset"
	matchservice "blackradar/api/service/match"
)

// handleAssetServiceError maps service error categories to HTTP responses.
func handleAssetServiceError(ec *appcontext.GinContext, err error) bool {
	var validationErr *assetservice.ValidationError
	var conflictErr *assetservice.ConflictError
	var forbiddenErr *assetservice.ForbiddenError
	var notFoundErr *assetservice.NotFoundError
	var assetDependencyErr *assetservice.DependencyError
	var matchDependencyErr *matchservice.DependencyError
	var assetInternalErr *assetservice.InternalError
	var matchInternalErr *matchservice.InternalError

	switch {
	case errors.As(err, &validationErr):
		return shared.HandleError(ec, http.StatusBadRequest, err, err.Error())
	case errors.As(err, &conflictErr):
		return shared.HandleError(ec, http.StatusConflict, err, err.Error())
	case errors.As(err, &forbiddenErr):
		return shared.HandleError(ec, http.StatusForbidden, err, err.Error())
	case errors.As(err, &notFoundErr):
		return shared.HandleError(ec, http.StatusNotFound, err, err.Error())
	case errors.As(err, &assetDependencyErr), errors.As(err, &matchDependencyErr):
		return shared.HandleError(ec, http.StatusBadGateway, err, "Asset dependency unavailable")
	case errors.As(err, &assetInternalErr), errors.As(err, &matchInternalErr):
		return shared.HandleError(ec, http.StatusInternalServerError, err, "Asset service failed")
	}

	return false
}
