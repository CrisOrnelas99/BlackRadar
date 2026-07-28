package jwtmiddleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"blackradar/api/model"
	requestcontext "blackradar/api/platform/requestcontext"
	userrepository "blackradar/api/repository/user"
)

// UserLookup resolves the current authenticated user.
//
// Implementations must apply soft-delete and account-status restrictions so
// disabled or deleted users cannot authenticate.
type UserLookup interface {
	FindByID(ec *requestcontext.GinContext, id string) (model.User, error)
}

// RefreshSessionLookup verifies that the token session remains active.
//
// The current project uses the JWT ID as a server-side session identifier for
// both access-token validation and refresh-token rotation.
type RefreshSessionLookup interface {
	FindActiveByTokenIDForUser(ec *requestcontext.GinContext, tokenID string, userID string) (model.RefreshSession, error)
}

var (
	ErrUnauthorized             = errors.New("Unauthorized")
	ErrDatabaseUnavailable      = errors.New("database unavailable")
	ErrInternalServer           = errors.New("internal server error")
	ErrJWTManagerRequired       = errors.New("JWT authentication manager is required")
	ErrJWTUserLookupRequired    = errors.New("JWT authentication user lookup is required")
	ErrJWTSessionLookupRequired = errors.New("JWT authentication session lookup is required")
)

// bearerToken parses an Authorization header containing exactly one bearer token.
func bearerToken(header string) (string, bool) {
	fields := strings.Fields(header)
	if len(fields) != 2 {
		return "", false
	}
	if !strings.EqualFold(fields[0], "Bearer") {
		return "", false
	}

	token := strings.TrimSpace(fields[1])
	if token == "" {
		return "", false
	}

	return token, true
}

// isAuthenticationNotFound reports whether an authentication lookup failed
// because the user or session does not exist.
func isAuthenticationNotFound(err error) bool {
	return errors.Is(err, userrepository.ErrRecordNotFound)
}

// abortUnauthorized returns a generic bearer authentication failure.
func abortUnauthorized(ctx *gin.Context) {
	ctx.Header("WWW-Authenticate", "Bearer")
	ctx.AbortWithStatusJSON(
		http.StatusUnauthorized,
		gin.H{"error": ErrUnauthorized.Error()},
	)
}

// abortDatabaseUnavailable returns a generic infrastructure failure response.
func abortDatabaseUnavailable(ctx *gin.Context) {
	ctx.AbortWithStatusJSON(
		http.StatusServiceUnavailable,
		gin.H{"error": ErrDatabaseUnavailable.Error()},
	)
}

// abortInternalError returns a generic internal authentication failure response.
func abortInternalError(ctx *gin.Context) {
	ctx.AbortWithStatusJSON(
		http.StatusInternalServerError,
		gin.H{"error": ErrInternalServer.Error()},
	)
}
