// Package permissions provides authorization middleware.
package permissions

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	requestcontext "blackradar/api/context"
	"blackradar/api/model"
)

// RequireAdmin allows only authenticated users with the administrator role.
//
// Authentication middleware must run before this middleware.
func RequireAdmin() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ec, err := requestcontext.FromGinContext(ctx)
		if err != nil {
			slog.Default().Error(
				"request context unavailable during authorization",
				slog.String("error", err.Error()),
			)
			abortInternalError(ctx)
			return
		}

		principal, err := ec.Principal()
		if err != nil {
			if errors.Is(err, requestcontext.ErrPrincipalNotSet) {
				ec.Logger().Warn("authorization attempted without authentication")
				abortUnauthorized(ctx)
				return
			}

			ec.Logger().Error(
				"failed to read authenticated principal",
				slog.String("error", err.Error()),
			)
			abortInternalError(ctx)
			return
		}

		if principal.Role != model.RoleAdmin {
			ec.Logger().Warn(
				"administrator permission denied",
				slog.String("user_id", principal.UserID),
				slog.String("organization_id", principal.OrganizationID),
				slog.String("role", principal.Role),
			)
			abortForbidden(ctx)
			return
		}

		ctx.Next()
	}
}

// abortUnauthorized returns a generic authentication-required response.
func abortUnauthorized(ctx *gin.Context) {
	ctx.Header("WWW-Authenticate", "Bearer")
	ctx.AbortWithStatusJSON(
		http.StatusUnauthorized,
		gin.H{"error": ErrUnauthorized.Error()},
	)
}

// abortForbidden returns a generic authorization failure response.
func abortForbidden(ctx *gin.Context) {
	ctx.AbortWithStatusJSON(
		http.StatusForbidden,
		gin.H{"error": ErrForbidden.Error()},
	)
}

// abortInternalError returns a generic internal authorization failure response.
func abortInternalError(ctx *gin.Context) {
	ctx.AbortWithStatusJSON(
		http.StatusInternalServerError,
		gin.H{"error": ErrInternalServer.Error()},
	)
}
