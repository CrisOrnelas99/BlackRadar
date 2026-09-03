// Package controller routes registers asset HTTP endpoints.
package controller

import (
	"github.com/gin-gonic/gin"

	"blackradar/api/middleware/permissions"
	ratelimit "blackradar/api/middleware/rate_limit"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

// RegisterRoutes registers asset routes.
func RegisterRoutes(protected *gin.RouterGroup, controller *AssetController) {
	protected.GET("/assets", appcontext.Wrap(controller.GetAssets))
	protected.GET("/assets/summary", appcontext.Wrap(controller.GetAssetSummary))
	protected.GET("/assets/:id/vulnerabilities", appcontext.Wrap(controller.GetAssetVulnerabilities))
	protected.GET("/assets/:id", appcontext.Wrap(controller.GetAsset))
	protected.POST("/assets", appcontext.Wrap(controller.CreateAsset))
	protected.PUT("/assets/:id", appcontext.Wrap(controller.UpdateAsset))
	protected.DELETE("/assets/:id", appcontext.Wrap(controller.DeleteAsset))

	protected.POST(
		"/assets/:id/vulnerabilities/:vulnerabilityId",
		permissions.RequirePermission(model.PermissionManageRelationships),
		appcontext.Wrap(controller.AssignVulnerability),
	)
	protected.POST(
		"/assets/:id/match-cpe/preview",
		permissions.RequirePermission(model.PermissionApproveCPE),
		ratelimit.AIRateLimit(),
		appcontext.Wrap(controller.PreviewAssetCPEMatch),
	)
	protected.POST(
		"/assets/:id/match-cpe/vulnerabilities/apply",
		permissions.RequirePermission(model.PermissionApproveCPE),
		ratelimit.AIRateLimit(),
		appcontext.Wrap(controller.ApplyAssetCPEMatch),
	)
	protected.DELETE(
		"/assets/:id/vulnerabilities/:vulnerabilityId",
		permissions.RequirePermission(model.PermissionManageRelationships),
		appcontext.Wrap(controller.RemoveVulnerability),
	)
}
