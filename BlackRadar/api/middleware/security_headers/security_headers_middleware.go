// Package securityheaders provides HTTP response security-header middleware.
package securityheaders

import (
	"github.com/gin-gonic/gin"
)

// SecurityHeaders adds defensive browser security headers.
//
// The policy is intended for a JSON API. Routes that serve HTML, Swagger UI,
// or downloadable content may require a separate policy.
func SecurityHeaders(cfg Config) gin.HandlerFunc {
	cfg = normalizeConfig(cfg)

	return func(ctx *gin.Context) {
		setSecurityHeaders(ctx)

		if cfg.EnableHSTS && requestIsSecure(ctx.Request, cfg.TrustForwardedProto) {
			ctx.Writer.Header().Set("Strict-Transport-Security", hstsHeader(cfg))
		}

		ctx.Next()
	}
}
