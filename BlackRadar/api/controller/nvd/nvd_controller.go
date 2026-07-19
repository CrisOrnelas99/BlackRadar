// Package controller provides HTTP handlers for NVD lookup operations.
package controller

import (
	"net/http"

	basecontroller "blackradar/api/controller"
	appcontext "blackradar/api/platform/requestcontext"
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
	return basecontroller.HandleServiceError(ec, err, basecontroller.ServiceErrorMessages{
		InvalidRequest:  "CVE ID must use format CVE-YYYY-NNNN",
		NotFound:        "CVE not found",
		RateLimited:     "CVE lookup rate limit exceeded",
		ExternalService: "CVE lookup failed",
	})
}
