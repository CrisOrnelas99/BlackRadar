// Package controller routes registers user authentication HTTP endpoints.
package controller

import (
	"github.com/gin-gonic/gin"

	ratelimit "blackradar/api/middleware/rate_limit"
	appcontext "blackradar/api/platform/requestcontext"
)

// RegisterRoutes registers authentication routes.
func RegisterRoutes(router *gin.RouterGroup, controller *UserController) {
	router.Use(ratelimit.AuthRateLimit())
	router.POST("/register", appcontext.Wrap(controller.Register))
	router.POST("/login", ratelimit.LoginRateLimit(), appcontext.Wrap(controller.Login))
	router.POST("/refresh", appcontext.Wrap(controller.Refresh))
	router.POST("/logout", appcontext.Wrap(controller.Logout))
}
