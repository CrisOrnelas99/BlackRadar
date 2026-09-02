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
	router.GET("/users", appcontext.Wrap(controller.ListUsers))
	router.GET("/users/:id", appcontext.Wrap(controller.GetUserForManagement))
	router.POST("/users", appcontext.Wrap(controller.CreateUser))
	router.PATCH("/users/:id/role", appcontext.Wrap(controller.ChangeUserRole))
	router.PATCH("/users/:id/status", appcontext.Wrap(controller.ChangeUserStatus))
}

// RegisterProtectedRoutes registers authenticated self-service user routes.
func RegisterProtectedRoutes(router *gin.RouterGroup, controller *UserController) {
	router.PUT("/profile", appcontext.Wrap(controller.UpdateProfile))
}
