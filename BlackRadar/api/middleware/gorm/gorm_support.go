package gormmiddleware

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

var ErrDatabaseUnavailable = errors.New("database unavailable")

// abortDatabaseUnavailable returns a generic database availability error.
func abortDatabaseUnavailable(ctx *gin.Context) {
	ctx.AbortWithStatusJSON(
		http.StatusInternalServerError,
		gin.H{"error": ErrDatabaseUnavailable.Error()},
	)
}
