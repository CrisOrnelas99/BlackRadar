package contextmiddleware

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
)

const requestIDHeader = "X-Request-ID"

func newRequestLogger(logger *slog.Logger, ctx *gin.Context, requestID string) *slog.Logger {
	return logger.With(
		slog.String("request_id", requestID),
		slog.String("method", ctx.Request.Method),
		slog.String("path", ctx.Request.URL.Path),
	)
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
