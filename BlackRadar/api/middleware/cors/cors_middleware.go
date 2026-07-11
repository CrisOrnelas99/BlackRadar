// Package cors provides explicit allowlist CORS middleware.
package cors

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Cors returns middleware that adds CORS headers for an explicit allowlist and handles OPTIONS preflight requests.
func Cors(allowedOrigins []string) gin.HandlerFunc {
	allowedOriginSet := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		allowedOriginSet[strings.TrimSpace(origin)] = struct{}{}
	}

	return func(c *gin.Context) {
		origin := strings.TrimSpace(c.GetHeader("Origin"))
		if origin != "" {
			if _, allowed := allowedOriginSet[origin]; !allowed {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Add("Vary", "Origin")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
