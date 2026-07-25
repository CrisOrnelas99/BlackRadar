package health

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// RegisterRoutes registers health and readiness routes.
func RegisterRoutes(router *gin.Engine, database *gorm.DB) {
	router.GET("/api/health", Health)
	router.GET("/api/ready", Ready(database))
}
