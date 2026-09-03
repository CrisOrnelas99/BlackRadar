// Package permissions provides authorization middleware.
package permissions

import (
	"errors"
	"log/slog"

	"github.com/gin-gonic/gin"

	"blackradar/api/model"
	requestcontext "blackradar/api/platform/requestcontext"
)

// RequirePermission allows only authenticated users with the requested capability.
//
// Authentication middleware must run before this middleware.
func RequirePermission(permission model.Permission) gin.HandlerFunc {
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

		if !model.HasPermission(principal.Role, permission) {
			ec.Logger().Warn(
				"permission denied",
				slog.String("user_id", principal.UserID),
				slog.String("role", principal.Role),
				slog.String("permission", string(permission)),
			)
			abortForbidden(ctx)
			return
		}

		ctx.Next()
	}
}
