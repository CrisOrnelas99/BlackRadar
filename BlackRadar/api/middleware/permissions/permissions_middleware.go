// Package permissions provides authorization middleware.
package permissions

import (
	"errors"
	"log/slog"

	"github.com/gin-gonic/gin"

	"blackradar/api/model"
	requestcontext "blackradar/api/platform/requestcontext"
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
				slog.String("role", principal.Role),
			)
			abortForbidden(ctx)
			return
		}

		ctx.Next()
	}
}
