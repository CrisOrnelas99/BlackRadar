// Package health routes registers health and readiness HTTP endpoints.
package health

import (
	servicehealth "blackradar/api/service/health"
	"github.com/gin-gonic/gin"
)

// RegisterRoutes registers health and readiness routes.
func RegisterRoutes(router *gin.Engine, database ReadinessChecker) {
	router.GET("/api/health", Health)
	router.GET("/api/ready", Ready(database))
}

// RegisterAdminRoutes registers detailed dependency health for administrators.
func RegisterAdminRoutes(router *gin.RouterGroup, dependencies servicehealth.Dependencies) {
	router.GET("/health/summary", Summary(servicehealth.NewSummaryChecker(dependencies)))
}
