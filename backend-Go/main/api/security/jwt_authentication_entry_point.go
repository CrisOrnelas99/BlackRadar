package security

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func JwtAuthenticationEntryPoint(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
}

