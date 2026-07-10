// Package middleware provides Gin middleware for request context setup, security guards, and request validation.
// RequestFilter inspects request paths and queries for unsafe patterns and fails closed on suspicious input.
package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	appcontext "blackradar/api/context"
)

// RequestFilter blocks suspicious requests that match common attack patterns.
// It protects the application from obvious path traversal, XSS, and SQL injection payloads
// before request handlers and business logic execute.
func RequestFilter() gin.HandlerFunc {
	return func(c *gin.Context) {
		data := strings.ToLower(c.Request.URL.Path + " " + c.Request.URL.RawQuery)
		reason := ""

		switch {
		case strings.Contains(data, "../"):
			reason = "PATH_TRAVERSAL"
		case strings.Contains(data, "<script") || strings.Contains(data, "%3cscript"):
			reason = "XSS_PATTERN"
		case strings.Contains(data, "' or ") || strings.Contains(data, "%27%20or%20") || strings.Contains(data, "union select") || strings.Contains(data, "drop table"):
			reason = "SQLI_PATTERN"
		}

		if reason != "" {
			appcontext.FromGinContext(c).Logger().Warn("blocked suspicious request",
				"method", c.Request.Method,
				"path", c.Request.URL.Path,
				"reason", reason,
				"source_ip", c.ClientIP(),
			)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": ErrSuspiciousRequest.Message})
			return
		}

		c.Next()
	}
}
