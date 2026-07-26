package permissions

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

var (
	ErrForbidden      = errors.New("forbidden")
	ErrUnauthorized   = errors.New("Unauthorized")
	ErrInternalServer = errors.New("internal server error")
)

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
