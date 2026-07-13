// Package securityheaders provides HTTP response security-header middleware.
package securityheaders

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

const defaultHSTSMaxAge = 31536000

// Config controls environment-sensitive security headers.
type Config struct {
	EnableHSTS          bool
	HSTSMaxAge          int
	HSTSIncludeDomains  bool
	TrustForwardedProto bool
}

// SecurityHeaders adds defensive browser security headers.
//
// The policy is intended for a JSON API. Routes that serve HTML, Swagger UI,
// or downloadable content may require a separate policy.
func SecurityHeaders(cfg Config) gin.HandlerFunc {
	if cfg.HSTSMaxAge <= 0 {
		cfg.HSTSMaxAge = defaultHSTSMaxAge
	}

	return func(ctx *gin.Context) {
		headers := ctx.Writer.Header()
		headers.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		headers.Set("X-Content-Type-Options", "nosniff")
		headers.Set("X-Frame-Options", "DENY")
		headers.Set("Referrer-Policy", "no-referrer")
		headers.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		if cfg.EnableHSTS && requestIsSecure(ctx.Request, cfg.TrustForwardedProto) {
			value := "max-age=" + strconv.Itoa(cfg.HSTSMaxAge)
			if cfg.HSTSIncludeDomains {
				value += "; includeSubDomains"
			}
			headers.Set("Strict-Transport-Security", value)
		}

		ctx.Next()
	}
}

// requestIsSecure reports whether a request reached the application through HTTPS.
func requestIsSecure(request *http.Request, trustForwardedProto bool) bool {
	if request == nil {
		return false
	}
	if request.TLS != nil {
		return true
	}
	if !trustForwardedProto {
		return false
	}

	return strings.EqualFold(
		strings.TrimSpace(request.Header.Get("X-Forwarded-Proto")),
		"https",
	)
}
