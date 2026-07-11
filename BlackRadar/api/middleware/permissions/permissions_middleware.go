// Package permissions provides authorization middleware.
package permissions

import (
	"net/http"

	"github.com/gin-gonic/gin"

	appcontext "blackradar/api/context"
	middlewareerrors "blackradar/api/middleware"
	baseservice "blackradar/api/service"
)

// RequireAdmin enforces that the authenticated request has the admin role.
// It reads the trusted role from GinContext and returns 403 Forbidden when authorization fails.
func RequireAdmin() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ec, err := appcontext.FromGinContext(ctx)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": middlewareerrors.ErrForbidden.Message})
			return
		}

		role, err := baseservice.AuthenticatedRole(ec)
		if err != nil || !baseservice.IsAdmin(role) {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": middlewareerrors.ErrForbidden.Message})
			return
		}

		ctx.Next()
	}
}
