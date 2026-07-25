// Package controller provides HTTP handlers for NVD lookup operations.
package controller

import (
	"errors"
	"net/http"

	basecontroller "blackradar/api/controller/shared"
	appcontext "blackradar/api/platform/requestcontext"
	matchservice "blackradar/api/service/match"
)

// NVDController handles read-only NVD lookup HTTP requests.
type NVDController struct {
	nvdLookupService matchservice.NVDLookupService
}

// NewNVDController creates a new NVDController.
func NewNVDController(nvdLookupService matchservice.NVDLookupService) *NVDController {
	return &NVDController{nvdLookupService: nvdLookupService}
}

// LookupCVE returns official NVD details for a CVE ID.
func (c *NVDController) LookupCVE(ec *appcontext.GinContext) {
	response, err := c.nvdLookupService.LookupCVE(ec, ec.Param("cveId"))
	if err != nil {
		if handleNVDLookupServiceError(ec, err) {
			return
		}
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "CVE lookup failed")
		return
	}

	ec.JSON(http.StatusOK, response)
}

func handleNVDLookupServiceError(ec *appcontext.GinContext, err error) bool {
	var validationErr *matchservice.ValidationError
	var notFoundErr *matchservice.NotFoundError
	var dependencyErr *matchservice.DependencyError
	var internalErr *matchservice.InternalError

	switch {
	case errors.As(err, &validationErr):
		return basecontroller.HandleError(ec, http.StatusBadRequest, err, "CVE ID must use format CVE-YYYY-NNNN")
	case errors.As(err, &notFoundErr):
		return basecontroller.HandleError(ec, http.StatusNotFound, err, "CVE not found")
	case errors.As(err, &dependencyErr):
		return basecontroller.HandleError(ec, http.StatusBadGateway, err, "CVE lookup failed")
	case errors.As(err, &internalErr):
		return basecontroller.HandleError(ec, http.StatusInternalServerError, err, "CVE lookup failed")
	}

	return false
}
