package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/security"
)

type UserLookup interface {
	ExistsByUsername(ec *appcontext.EchoContext, username string) (bool, error)
}

func JwtAuthenticationFilter(jwtService *security.JwtService, users UserLookup) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		header := ctx.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			security.JwtAuthenticationEntryPoint(ctx)
			return
		}

		token := strings.TrimPrefix(header, "Bearer ")
		username, err := jwtService.ExtractUsername(token)
		if err != nil {
			security.JwtAuthenticationEntryPoint(ctx)
			return
		}

		ec := appcontext.FromGinContext(ctx)
		exists, err := users.ExistsByUsername(ec, username)
		if err != nil || !exists {
			security.JwtAuthenticationEntryPoint(ctx)
			return
		}

		ctx.Set("username", username)
		ctx.Next()
	}
}
