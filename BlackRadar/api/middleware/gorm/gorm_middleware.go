// Package gormmiddleware provides request-scoped GORM database middleware.
package gormmiddleware

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	requestcontext "blackradar/api/context"
)

// RequestDatabase adds a request-context-aware database session to GinContext.
//
// It does not open a transaction. Services and repositories should define
// explicit transaction boundaries around business operations that require
// atomicity.
func RequestDatabase(database *gorm.DB) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if database == nil {
			abortDatabaseUnavailable(ctx)
			return
		}

		appContext, err := requestcontext.FromGinContext(ctx)
		if err != nil {
			slog.Default().Error(
				"request context unavailable for database middleware",
				slog.String("error", err.Error()),
			)
			abortDatabaseUnavailable(ctx)
			return
		}

		requestDatabase := database.WithContext(ctx.Request.Context())
		appContext.SetDatabase(requestDatabase)
		defer appContext.SetDatabase(nil)

		ctx.Next()
	}
}

// GormMiddleware preserves the previous middleware name for existing callers.
func GormMiddleware(database *gorm.DB) gin.HandlerFunc {
	return RequestDatabase(database)
}

// abortDatabaseUnavailable returns a generic database availability error.
func abortDatabaseUnavailable(ctx *gin.Context) {
	ctx.AbortWithStatusJSON(
		http.StatusInternalServerError,
		gin.H{"error": ErrDatabaseUnavailable.Error()},
	)
}
