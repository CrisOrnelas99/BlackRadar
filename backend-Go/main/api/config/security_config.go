package config

import (
	"github.com/gin-gonic/gin"

	"secureops/backend-go/api/middleware"
	"secureops/backend-go/api/security"
)

func SecurityConfig(jwtService *security.JwtService, userLookup middleware.UserLookup) gin.HandlerFunc {
	return middleware.JwtAuthenticationFilter(jwtService, userLookup)
}

