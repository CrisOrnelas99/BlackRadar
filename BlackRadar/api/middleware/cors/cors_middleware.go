// Package cors provides explicit allowlist-based CORS middleware.
package cors

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// New creates CORS middleware from an explicit allowlist.
//
// Configuration errors are returned during application startup rather than
// being discovered while handling requests.
func New(cfg Config) (gin.HandlerFunc, error) {
	policy, err := buildPolicy(cfg)
	if err != nil {
		return nil, err
	}

	return policy.corsHandler(), nil
}

// corsHandler returns the Gin handler that applies the prepared CORS policy.
func (policy policy) corsHandler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		origin := strings.TrimSpace(ctx.GetHeader("Origin"))
		if origin == "" {
			ctx.Next()
			return
		}

		if _, allowed := policy.allowedOrigins[origin]; !allowed {
			if ctx.Request.Method == http.MethodOptions {
				ctx.AbortWithStatus(http.StatusForbidden)
				return
			}

			ctx.Next()
			return
		}

		setVaryHeader(ctx.Writer.Header(), "Origin")
		ctx.Header("Access-Control-Allow-Origin", origin)
		if policy.allowCredentials {
			ctx.Header("Access-Control-Allow-Credentials", "true")
		}
		if policy.exposedHeader != "" {
			ctx.Header("Access-Control-Expose-Headers", policy.exposedHeader)
		}

		if ctx.Request.Method != http.MethodOptions {
			ctx.Next()
			return
		}

		policy.handlePreflight(ctx)
	}
}
