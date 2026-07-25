// Package controller provides HTTP handlers for NVD lookup operations.
package controller

import (
	"net/http"

	shared "blackradar/api/controller/shared"
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
		shared.HandleError(ec, http.StatusInternalServerError, err, "CVE lookup failed")
		return
	}

	ec.JSON(http.StatusOK, response)
}
