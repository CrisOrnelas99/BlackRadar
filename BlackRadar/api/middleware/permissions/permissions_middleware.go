// Package permissions provides authorization middleware.
package permissions

import (
	"net/http"

	"github.com/gin-gonic/gin"

	middlewareerrors "blackradar/api/middleware"
	appcontext "blackradar/api/requestContext"
	baseservice "blackradar/api/service"
)

// RequireAdmin enforces that the authenticated request has the admin role.
// It reads the trusted role from GinContext and returns 403 Forbidden when authorization fails.
func RequireAdmin() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ec := appcontext.FromGinContext(ctx)
		if !baseservice.IsAdmin(ec.UserRole()) {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": middlewareerrors.ErrForbidden.Message})
			return
		}

		ctx.Next()
	}
}
