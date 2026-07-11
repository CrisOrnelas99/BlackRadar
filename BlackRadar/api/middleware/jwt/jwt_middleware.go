// Package jwtmiddleware provides JWT authentication middleware.
package jwtmiddleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	appcontext "blackradar/api/context"
	middlewareerrors "blackradar/api/middleware"
	"blackradar/api/model"
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

		ec, err := appcontext.FromGinContext(ctx)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": middlewareerrors.ErrUnauthorized.Message})
			return
		}
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

		if err := ec.SetPrincipal(appcontext.Principal{
			UserID:         user.ID,
			Username:       claims.Subject,
			Role:           user.Role,
			OrganizationID: user.OrganizationID,
		}); err != nil {
			JWTAuthenticationEntryPoint(ctx)
			return
		}
		ctx.Next()
	}
}

// JWTAuthenticationEntryPoint aborts the request with a standard 401 Unauthorized response.
func JWTAuthenticationEntryPoint(ctx *gin.Context) {
	ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": middlewareerrors.ErrUnauthorized.Message})
}
