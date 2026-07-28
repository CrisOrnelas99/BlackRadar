// Package health routes registers health and readiness HTTP endpoints.
package health

import (
	"github.com/gin-gonic/gin"
)

// RegisterRoutes registers health and readiness routes.
func RegisterRoutes(router *gin.Engine, database ReadinessChecker) {
	router.GET("/api/health", Health)
	router.GET("/api/ready", Ready(database))
}
