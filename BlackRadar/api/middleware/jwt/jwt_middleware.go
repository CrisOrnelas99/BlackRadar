// Package jwtmiddleware provides JWT authentication middleware.
package jwtmiddleware

import (
	"log/slog"
	"strings"

	"github.com/gin-gonic/gin"

	commonjwt "blackradar/api/common/jwt"
	requestcontext "blackradar/api/platform/requestcontext"
)

// Authentication validates bearer access tokens and stores the authenticated
// principal on request context.
func Authentication(
	jwtManager *commonjwt.Manager,
	users UserLookup,
	sessions RefreshSessionLookup,
) (gin.HandlerFunc, error) {
	if jwtManager == nil {
		return nil, ErrJWTManagerRequired
	}
	if users == nil {
		return nil, ErrJWTUserLookupRequired
	}
	if sessions == nil {
		return nil, ErrJWTSessionLookupRequired
	}

	return func(ctx *gin.Context) {
		ec, err := requestcontext.FromGinContext(ctx)
		if err != nil {
			slog.Default().Error(
				"request context unavailable during authentication",
				slog.String("error", err.Error()),
			)
			abortInternalError(ctx)
			return
		}

		token, ok := bearerToken(ctx.GetHeader("Authorization"))
		if !ok {
			ec.Logger().Debug("authorization bearer token missing")
			abortUnauthorized(ctx)
			return
		}

		claims, err := jwtManager.ExtractAccessClaims(token)
		if err != nil {
			ec.Logger().Debug(
				"access token validation failed",
				slog.String("error", err.Error()),
			)
			abortUnauthorized(ctx)
			return
		}

		if strings.TrimSpace(claims.Subject) == "" || strings.TrimSpace(claims.ID) == "" {
			ec.Logger().Warn("validated token contains incomplete identity claims")
			abortUnauthorized(ctx)
			return
		}

		user, err := users.FindByID(ec, claims.Subject)
		if err != nil {
			if isAuthenticationNotFound(err) {
				ec.Logger().Warn(
					"access token subject does not identify an active user",
					slog.String("user_id", claims.Subject),
				)
				abortUnauthorized(ctx)
				return
			}

			ec.Logger().Error(
				"authenticated user lookup failed",
				slog.String("user_id", claims.Subject),
				slog.String("error", err.Error()),
			)
			abortDatabaseUnavailable(ctx)
			return
		}

		if strings.TrimSpace(user.ID) == "" || user.ID != claims.Subject {
			ec.Logger().Warn(
				"authenticated user identity mismatch",
				slog.String("subject", claims.Subject),
			)
			abortUnauthorized(ctx)
			return
		}

		if _, err := sessions.FindActiveByTokenIDForUser(ec, claims.ID, user.ID); err != nil {
			if isAuthenticationNotFound(err) {
				ec.Logger().Warn(
					"access token session is inactive",
					slog.String("user_id", user.ID),
					slog.String("token_id", claims.ID),
				)
				abortUnauthorized(ctx)
				return
			}

			ec.Logger().Error(
				"access token session lookup failed",
				slog.String("user_id", user.ID),
				slog.String("error", err.Error()),
			)
			abortDatabaseUnavailable(ctx)
			return
		}

		if err := ec.SetPrincipal(requestcontext.Principal{
			UserID:   user.ID,
			Username: user.Username,
			Role:     user.Role,
		}); err != nil {
			ec.Logger().Error(
				"failed to establish authenticated principal",
				slog.String("user_id", user.ID),
				slog.String("error", err.Error()),
			)
			abortInternalError(ctx)
			return
		}

		ctx.Next()
	}, nil
}
