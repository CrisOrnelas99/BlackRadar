// Package controller routes registers user authentication HTTP endpoints.
package controller

import (
	"github.com/gin-gonic/gin"

	ratelimit "blackradar/api/middleware/rate_limit"
	appcontext "blackradar/api/platform/requestcontext"
)

// RegisterRoutes registers public authentication routes.
func RegisterRoutes(router *gin.RouterGroup, controller *UserController) {
	router.Use(ratelimit.AuthRateLimit())
	router.POST("/login", ratelimit.LoginRateLimit(), appcontext.Wrap(controller.Login))
	router.POST("/refresh", appcontext.Wrap(controller.Refresh))
	router.POST("/logout", appcontext.Wrap(controller.Logout))
}

// RegisterAdminRoutes registers administrator-only user management routes.
func RegisterAdminRoutes(router *gin.RouterGroup, controller *UserController) {
	router.POST("/users", appcontext.Wrap(controller.CreateUser))
}

// RegisterProtectedRoutes registers authenticated self-service user routes.
func RegisterProtectedRoutes(router *gin.RouterGroup, controller *UserController) {
	router.PUT("/profile", appcontext.Wrap(controller.UpdateProfile))
}
