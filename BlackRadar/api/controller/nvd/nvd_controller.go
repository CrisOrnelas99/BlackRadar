// Package controller provides HTTP handlers for NVD lookup operations.
package controller

import (
	"errors"
	"net/http"

	basecontroller "blackradar/api/controller"
	appcontext "blackradar/api/context"
	baseservice "blackradar/api/service"
)

// NVDController handles read-only NVD lookup HTTP requests.
type NVDController struct {
	nvdLookupService baseservice.NVDLookupService
}

// NewNVDController creates a new NVDController.
func NewNVDController(nvdLookupService baseservice.NVDLookupService) *NVDController {
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
	var serviceErr *baseservice.ServiceError
	if errors.As(err, &serviceErr) {
		if errors.Is(err, baseservice.ErrInvalidRequestData) {
			basecontroller.HandleError(ec, http.StatusBadRequest, err, "CVE ID must use format CVE-YYYY-NNNN")
			return true
		}
		if errors.Is(err, baseservice.ErrNotFound) {
			basecontroller.HandleError(ec, http.StatusNotFound, err, "CVE not found")
			return true
		}
		if errors.Is(err, baseservice.ErrRateLimited) {
			basecontroller.HandleError(ec, http.StatusTooManyRequests, err, "CVE lookup rate limit exceeded")
			return true
		}
		if errors.Is(err, baseservice.ErrForbidden) {
			basecontroller.HandleError(ec, http.StatusForbidden, err, baseservice.ErrForbidden.Error())
			return true
		}
		if errors.Is(err, baseservice.ErrExternalService) {
			basecontroller.HandleError(ec, http.StatusBadGateway, err, "CVE lookup failed")
			return true
		}
	}
	return false
}
