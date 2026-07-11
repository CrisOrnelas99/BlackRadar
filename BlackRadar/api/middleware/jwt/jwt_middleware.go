// Package jwtmiddleware provides JWT authentication middleware.
package jwtmiddleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	middlewareerrors "blackradar/api/middleware"
	"blackradar/api/model"
	appcontext "blackradar/api/requestContext"
	sharedjwt "blackradar/api/shared/jwt"
)

// UserLookup defines how authentication middleware resolves a username to a user record.
// It accepts a request-scoped GinContext so lookup implementations can use the current request metadata.
type UserLookup interface {
	ExistsByUsername(ec *appcontext.GinContext, username string) (bool, error)
	FindByUsername(ec *appcontext.GinContext, username string) (model.User, error)
}

// RefreshSessionLookup defines how authentication middleware verifies that a token session is still active.
type RefreshSessionLookup interface {
	FindActiveByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID string) (model.RefreshSession, error)
}

// JWTAuthenticationFilter validates Authorization bearer tokens, resolves the authenticated user,
// and stores typed authentication state on request context. It fails closed for missing, invalid,
// or unverifiable authentication.
func JWTAuthenticationFilter(jwtManager *sharedjwt.JWTManager, users UserLookup, sessions RefreshSessionLookup) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		header := ctx.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			JWTAuthenticationEntryPoint(ctx)
			return
		}

		token := strings.TrimPrefix(header, "Bearer ")
		claims, err := jwtManager.ExtractAccessClaims(token)
		if err != nil {
			JWTAuthenticationEntryPoint(ctx)
			return
		}

		ec := appcontext.FromGinContext(ctx)
		exists, err := users.ExistsByUsername(ec, claims.Subject)
		if err != nil || !exists {
			JWTAuthenticationEntryPoint(ctx)
			return
		}

		user, err := users.FindByUsername(ec, claims.Subject)
		if err != nil {
			JWTAuthenticationEntryPoint(ctx)
			return
		}

		if sessions == nil {
			JWTAuthenticationEntryPoint(ctx)
			return
		}

		if _, err := sessions.FindActiveByTokenIDForUser(ec, claims.ID, user.ID); err != nil {
			JWTAuthenticationEntryPoint(ctx)
			return
		}

		ec.SetUsername(claims.Subject)
		ec.SetUserID(user.ID)
		ec.SetOrganizationID(user.OrganizationID)
		ec.SetUserRole(user.Role)
		ctx.Next()
	}
}

// JWTAuthenticationEntryPoint aborts the request with a standard 401 Unauthorized response.
func JWTAuthenticationEntryPoint(ctx *gin.Context) {
	ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": middlewareerrors.ErrUnauthorized.Message})
}
