// Package controller routes registers AI HTTP endpoints.
package controller

import (
	"github.com/gin-gonic/gin"

	ratelimit "blackradar/api/middleware/rate_limit"
	appcontext "blackradar/api/platform/requestcontext"
)

// RegisterRoutes registers AI diagnostic routes.
func RegisterRoutes(router *gin.RouterGroup, controller *AIController) {
	ai := router.Group("/ai", ratelimit.AIRateLimit())
	ai.GET("/test", appcontext.Wrap(controller.TestProvider))
	ai.POST("/message", appcontext.Wrap(controller.SendMessage))
}
