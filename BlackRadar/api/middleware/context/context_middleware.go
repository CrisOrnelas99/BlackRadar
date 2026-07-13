// Package contextmiddleware provides middleware that initializes request-scoped
// application context.
package contextmiddleware

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	commonid "blackradar/api/common/id"
	requestcontext "blackradar/api/context"
)

const requestIDHeader = "X-Request-ID"

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

		requestLogger := logger.With(
			slog.String("request_id", requestID),
			slog.String("method", ctx.Request.Method),
			slog.String("path", ctx.Request.URL.Path),
		)

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

// ClientRequestID returns a validated client-provided request ID.
//
// Internally generated IDs remain the primary correlation identifiers.
func ClientRequestID(ctx *gin.Context) string {
	value := strings.TrimSpace(ctx.GetHeader(requestIDHeader))
	if len(value) == 0 || len(value) > 128 {
		return ""
	}

	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '-':
		case character == '_':
		case character == '.':
		default:
			return ""
		}
	}

	return value
}

// logRequestCompletion records bounded request metadata after downstream
// handlers finish or unwind because of a panic.
func logRequestCompletion(ctx *gin.Context, logger *slog.Logger, startedAt time.Time) {
	duration := time.Since(startedAt)
	logger.Info(
		"request completed",
		slog.Int("status", ctx.Writer.Status()),
		slog.Int("response_size", ctx.Writer.Size()),
		slog.Int64("duration_ms", duration.Milliseconds()),
		slog.Bool("aborted", ctx.IsAborted()),
		slog.Int("error_count", len(ctx.Errors)),
	)
}
