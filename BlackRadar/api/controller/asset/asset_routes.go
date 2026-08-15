// Package controller routes registers asset HTTP endpoints.
package controller

import (
	"github.com/gin-gonic/gin"

	ratelimit "blackradar/api/middleware/rate_limit"
	appcontext "blackradar/api/platform/requestcontext"
)

// RegisterRoutes registers asset routes.
func RegisterRoutes(protected *gin.RouterGroup, adminOnly *gin.RouterGroup, controller *AssetController) {
	protected.GET("/assets", appcontext.Wrap(controller.GetAssets))
	protected.GET("/assets/:id/vulnerabilities", appcontext.Wrap(controller.GetAssetVulnerabilities))
	protected.GET("/assets/:id", appcontext.Wrap(controller.GetAsset))
	protected.POST("/assets", appcontext.Wrap(controller.CreateAsset))
	protected.PUT("/assets/:id", appcontext.Wrap(controller.UpdateAsset))
	protected.DELETE("/assets/:id", appcontext.Wrap(controller.DeleteAsset))

	adminOnly.POST("/assets/:id/vulnerabilities/:vulnerabilityId", appcontext.Wrap(controller.AssignVulnerability))
	adminOnly.POST("/assets/:id/match-cpe/preview", ratelimit.AIRateLimit(), appcontext.Wrap(controller.PreviewAssetCPEMatch))
	adminOnly.POST("/assets/:id/match-cpe/vulnerabilities/apply", ratelimit.AIRateLimit(), appcontext.Wrap(controller.ApplyAssetCPEMatch))
	adminOnly.DELETE("/assets/:id/vulnerabilities/:vulnerabilityId", appcontext.Wrap(controller.RemoveVulnerability))
}
