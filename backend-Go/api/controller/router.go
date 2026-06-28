// Package controller provides shared HTTP helpers, health handling, and route wiring for the API.
package controller

import (
	"github.com/gin-gonic/gin"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/middleware"
	"secureops/backend-go/api/security"
)

// RouteHandlers groups the controller functions used when wiring HTTP routes.
type RouteHandlers struct {
	RegisterAuth             func(*appcontext.GinContext)
	LoginAuth                func(*appcontext.GinContext)
	RefreshAuth              func(*appcontext.GinContext)
	LogoutAuth               func(*appcontext.GinContext)
	GetAssets                func(*appcontext.GinContext)
	GetAsset                 func(*appcontext.GinContext)
	CreateAsset              func(*appcontext.GinContext)
	UpdateAsset              func(*appcontext.GinContext)
	DeleteAsset              func(*appcontext.GinContext)
	AssignVulnerability      func(*appcontext.GinContext)
	AssignVulnerabilityByCVE func(*appcontext.GinContext)
	RemoveVulnerability      func(*appcontext.GinContext)
	GetVulnerabilities       func(*appcontext.GinContext)
	GetVulnerability         func(*appcontext.GinContext)
	CreateVulnerability      func(*appcontext.GinContext)
	UpdateVulnerability      func(*appcontext.GinContext)
	DeleteVulnerability      func(*appcontext.GinContext)
	LookupCVE                func(*appcontext.GinContext)
}

// RegisterRoutes centralizes all route registrations for the application.
func RegisterRoutes(router *gin.Engine, jwtManager *security.JWTManager, userLookup middleware.UserLookup, sessions middleware.RefreshSessionLookup, handlers RouteHandlers) {
	router.GET("/api/health", Health)
	router.POST("/api/auth/register", appcontext.Wrap(handlers.RegisterAuth))
	router.POST("/api/auth/login", appcontext.Wrap(handlers.LoginAuth))
	router.POST("/api/auth/refresh", appcontext.Wrap(handlers.RefreshAuth))
	router.POST("/api/auth/logout", appcontext.Wrap(handlers.LogoutAuth))

	protected := router.Group("/api")
	protected.Use(middleware.JWTAuthenticationFilter(jwtManager, userLookup, sessions))
	{
		protected.GET("/assets", appcontext.Wrap(handlers.GetAssets))
		protected.GET("/assets/:id", appcontext.Wrap(handlers.GetAsset))
		protected.POST("/assets", appcontext.Wrap(handlers.CreateAsset))
		protected.PUT("/assets/:id", appcontext.Wrap(handlers.UpdateAsset))
		protected.DELETE("/assets/:id", appcontext.Wrap(handlers.DeleteAsset))
		protected.POST("/assets/:id/vulnerabilities/:vulnerabilityId", appcontext.Wrap(handlers.AssignVulnerability))
		protected.POST("/assets/:id/vulnerabilities/cve/:cveId", appcontext.Wrap(handlers.AssignVulnerabilityByCVE))
		protected.DELETE("/assets/:id/vulnerabilities/:vulnerabilityId", appcontext.Wrap(handlers.RemoveVulnerability))

		protected.GET("/vulnerabilities", appcontext.Wrap(handlers.GetVulnerabilities))
		protected.GET("/vulnerabilities/:id", appcontext.Wrap(handlers.GetVulnerability))
		protected.POST("/vulnerabilities", appcontext.Wrap(handlers.CreateVulnerability))
		protected.PUT("/vulnerabilities/:id", appcontext.Wrap(handlers.UpdateVulnerability))
		protected.DELETE("/vulnerabilities/:id", appcontext.Wrap(handlers.DeleteVulnerability))

		protected.GET("/nvd/cves/:cveId", appcontext.Wrap(handlers.LookupCVE))
	}
}
