// Package controller routes registers backend AI HTTP endpoints.
package controller

import (
	"github.com/gin-gonic/gin"

	ratelimit "blackradar/api/middleware/rate_limit"
	appcontext "blackradar/api/platform/requestcontext"
)

// RegisterDashboardRoutes registers authenticated dashboard AI routes.
func RegisterDashboardRoutes(router *gin.RouterGroup, controller *AIController) {
	ai := router.Group("/dashboard")
	ai.GET("/ai-summary", appcontext.Wrap(controller.GetDashboardSummary))
	ai.POST("/ai-summary", ratelimit.AIRateLimit(), appcontext.Wrap(controller.GenerateDashboardSummary))
}
