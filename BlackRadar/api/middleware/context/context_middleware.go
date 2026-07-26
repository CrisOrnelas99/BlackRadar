// Package contextmiddleware provides middleware that initializes request-scoped
// application context.
package contextmiddleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	commonid "blackradar/api/common/id"
	requestcontext "blackradar/api/platform/requestcontext"
)

// RequestContext initializes request metadata, logging, and the request-scoped
// GinContext wrapper.
//
// This middleware must run early so downstream middleware and handlers can
// access authenticated identity, request IDs, and request-scoped database state.
func RequestContext(logger *slog.Logger) gin.HandlerFunc {
	if logger == nil {
		logger = slog.Default()
	}

	return func(ctx *gin.Context) {
		startedAt := time.Now()

		requestID, err := commonid.New()
		if err != nil {
			logger.Error("failed to generate request ID", slog.String("error", err.Error()))
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		requestLogger := newRequestLogger(logger, ctx, requestID)

		requestcontext.SetGinContext(
			ctx,
			requestcontext.NewGinContext(ctx, requestID, requestLogger),
		)
		ctx.Header(requestIDHeader, requestID)

		requestLogger.Info("request started")
		defer logRequestCompletion(ctx, requestLogger, startedAt)

		ctx.Next()
	}
}
