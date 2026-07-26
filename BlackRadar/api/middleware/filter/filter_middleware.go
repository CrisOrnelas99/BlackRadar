// Package filter provides request filtering middleware.
package filter

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

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
	maximumPathLength := maximumPathLengthFromConfig(cfg)

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
