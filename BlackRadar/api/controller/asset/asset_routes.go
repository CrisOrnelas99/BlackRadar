package controller

import (
	"github.com/gin-gonic/gin"

	ratelimit "blackradar/api/middleware/rate_limit"
	appcontext "blackradar/api/platform/requestcontext"
)

// RegisterRoutes registers asset routes.
func RegisterRoutes(protected *gin.RouterGroup, adminOnly *gin.RouterGroup, controller *AssetController) {
	protected.GET("/assets", appcontext.Wrap(controller.GetAssets))
	protected.GET("/assets/:id", appcontext.Wrap(controller.GetAsset))
	protected.POST("/assets", appcontext.Wrap(controller.CreateAsset))
	protected.PUT("/assets/:id", appcontext.Wrap(controller.UpdateAsset))
	protected.DELETE("/assets/:id", appcontext.Wrap(controller.DeleteAsset))

	adminOnly.POST("/assets/:id/vulnerabilities/:vulnerabilityId", appcontext.Wrap(controller.AssignVulnerability))
	adminOnly.POST("/assets/:id/match-cpe/vulnerabilities", ratelimit.AIRateLimit(), appcontext.Wrap(controller.MatchAssetCPEAndAttachVulnerabilities))
	adminOnly.DELETE("/assets/:id/vulnerabilities/:vulnerabilityId", appcontext.Wrap(controller.RemoveVulnerability))
}
