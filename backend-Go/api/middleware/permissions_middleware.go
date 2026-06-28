// Package middleware provides Gin middleware for request context setup, security guards, and request validation.
// Authorization middleware in this package enforces role-based access control on protected endpoints.
package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/security"
)

// RequireAdmin enforces that the authenticated request has the admin role.
// It reads the trusted role from GinContext and returns 403 Forbidden when authorization fails.
func RequireAdmin() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ec := appcontext.FromGinContext(ctx)
		if !security.IsAdmin(ec.UserRole()) {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": ErrForbidden.Message})
			return
		}

		ctx.Next()
	}
}
