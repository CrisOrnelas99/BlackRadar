// Package filter provides request filtering middleware.
package filter

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	requestcontext "blackradar/api/context"
)

const defaultMaximumPathLength = 2048

// Config defines request-path safety limits.
type Config struct {
	MaximumPathLength int
}

// RequestFilter creates request filtering middleware with default limits.
func RequestFilter() gin.HandlerFunc {
	return New(Config{})
}

// New creates middleware that rejects malformed or unsafe request paths.
//
// This middleware does not attempt to detect SQL injection or XSS. Those
// threats are handled through parameterized queries, input validation, output
// escaping, and browser security controls.
func New(cfg Config) gin.HandlerFunc {
	maximumPathLength := cfg.MaximumPathLength
	if maximumPathLength <= 0 {
		maximumPathLength = defaultMaximumPathLength
	}

	return func(ctx *gin.Context) {
		if err := validatePath(ctx.Request.URL.EscapedPath(), maximumPathLength); err != nil {
			logRejectedRequest(ctx, err)
			ctx.AbortWithStatusJSON(
				http.StatusBadRequest,
				gin.H{"error": ErrInvalidRequestPath.Error()},
			)
			return
		}

		ctx.Next()
	}
}

// validatePath rejects malformed paths and obvious traversal attempts.
func validatePath(escapedPath string, maximumLength int) error {
	if len(escapedPath) > maximumLength {
		return fmt.Errorf(
			"%w: %d > %d",
			ErrRequestPathTooLong,
			len(escapedPath),
			maximumLength,
		)
	}

	if containsControlCharacter(escapedPath) {
		return ErrRequestPathControlChar
	}

	decodedPath, err := url.PathUnescape(escapedPath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRequestPathBadEncoding, err)
	}

	if containsControlCharacter(decodedPath) {
		return ErrRequestPathControlChar
	}

	normalizedPath := strings.ReplaceAll(decodedPath, `\`, "/")
	for _, segment := range strings.Split(normalizedPath, "/") {
		if segment == ".." {
			return ErrRequestPathTraversal
		}
	}

	return nil
}

// containsControlCharacter reports whether a value contains ASCII control characters.
func containsControlCharacter(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}

	return false
}

// logRejectedRequest records rejected request metadata without logging query strings or bodies.
func logRejectedRequest(ctx *gin.Context, err error) {
	logger := slog.Default()
	if requestContext, contextErr := requestcontext.FromGinContext(ctx); contextErr == nil {
		logger = requestContext.Logger()
	}

	reason := err.Error()
	switch {
	case errors.Is(err, ErrRequestPathTooLong):
		reason = ErrRequestPathTooLong.Error()
	case errors.Is(err, ErrRequestPathControlChar):
		reason = ErrRequestPathControlChar.Error()
	case errors.Is(err, ErrRequestPathBadEncoding):
		reason = ErrRequestPathBadEncoding.Error()
	case errors.Is(err, ErrRequestPathTraversal):
		reason = ErrRequestPathTraversal.Error()
	}

	logger.Warn(
		"rejected unsafe request",
		slog.String("method", ctx.Request.Method),
		slog.String("path", ctx.Request.URL.Path),
		slog.String("reason", reason),
	)
}
