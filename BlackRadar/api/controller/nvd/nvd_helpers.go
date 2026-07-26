package controller

import (
	"errors"
	"net/http"

	shared "blackradar/api/controller/shared"
	appcontext "blackradar/api/platform/requestcontext"
	assetmatchservice "blackradar/api/service/asset_match"
)

// handleNVDLookupServiceError maps service error categories to HTTP responses.
func handleNVDLookupServiceError(ec *appcontext.GinContext, err error) bool {
	var validationErr *assetmatchservice.ValidationError
	var notFoundErr *assetmatchservice.NotFoundError
	var dependencyErr *assetmatchservice.DependencyError
	var internalErr *assetmatchservice.InternalError

	switch {
	case errors.As(err, &validationErr):
		return shared.HandleError(ec, http.StatusBadRequest, err, "CVE ID must use format CVE-YYYY-NNNN")
	case errors.As(err, &notFoundErr):
		return shared.HandleError(ec, http.StatusNotFound, err, "CVE not found")
	case errors.As(err, &dependencyErr):
		return shared.HandleError(ec, http.StatusBadGateway, err, "CVE lookup failed")
	case errors.As(err, &internalErr):
		return shared.HandleError(ec, http.StatusInternalServerError, err, "CVE lookup failed")
	}

	return false
}
