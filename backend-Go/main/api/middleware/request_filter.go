package middleware

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

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
			log.Printf("Blocked suspicious request: method=%s path=%s reason=%s source_ip=%s", c.Request.Method, c.Request.URL.Path, reason, c.ClientIP())
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": ErrSuspiciousRequest.Message})
			return
		}

		c.Next()
	}
}

