// Package middleware provides Gin middleware for request context setup, security guards, and request validation.
// SecurityHeaders sets strict response headers to protect the application from common browser-based threats.
package middleware

import "github.com/gin-gonic/gin"

// SecurityHeaders adds standard security response headers for CSP, HSTS, MIME sniffing, frame options,
// referrer policy, and feature policy.
func SecurityHeaders() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		headers := ctx.Writer.Header()
		headers.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		headers.Set("X-Content-Type-Options", "nosniff")
		headers.Set("X-Frame-Options", "DENY")
		headers.Set("Referrer-Policy", "no-referrer")
		headers.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		ctx.Next()
	}
}
