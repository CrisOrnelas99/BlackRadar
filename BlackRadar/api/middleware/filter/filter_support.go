package filter

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	requestcontext "blackradar/api/platform/requestcontext"
)

const defaultMaximumPathLength = 2048

var (
	ErrInvalidRequestPath     = errors.New("invalid request path")
	ErrRequestPathTooLong     = errors.New("request path exceeds maximum length")
	ErrRequestPathControlChar = errors.New("request path contains a control character")
	ErrRequestPathBadEncoding = errors.New("request path contains malformed encoding")
	ErrRequestPathTraversal   = errors.New("request path contains traversal segments")
)

// Config defines request-path safety limits.
type Config struct {
	MaximumPathLength int
}

func maximumPathLengthFromConfig(cfg Config) int {
	if cfg.MaximumPathLength > 0 {
		return cfg.MaximumPathLength
	}

	return defaultMaximumPathLength
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

	logger.Warn(
		"rejected unsafe request",
		slog.String("method", ctx.Request.Method),
		slog.String("path", ctx.Request.URL.Path),
		slog.String("reason", rejectionReason(err)),
	)
}

func rejectionReason(err error) string {
	switch {
	case errors.Is(err, ErrRequestPathTooLong):
		return ErrRequestPathTooLong.Error()
	case errors.Is(err, ErrRequestPathControlChar):
		return ErrRequestPathControlChar.Error()
	case errors.Is(err, ErrRequestPathBadEncoding):
		return ErrRequestPathBadEncoding.Error()
	case errors.Is(err, ErrRequestPathTraversal):
		return ErrRequestPathTraversal.Error()
	default:
		return err.Error()
	}
}
