// Package controller provides shared HTTP helpers, health handling, and route wiring for the API.
package controller

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"blackradar/api/controller/health"
	jwtmiddleware "blackradar/api/middleware/jwt"
	"blackradar/api/middleware/permissions"
	ratelimit "blackradar/api/middleware/rate_limit"
	appcontext "blackradar/api/requestContext"
	sharedjwt "blackradar/api/shared/jwt"
)

// RouteHandlers groups the controller functions used when wiring HTTP routes.
type RouteHandlers struct {
	RegisterAuth           func(*appcontext.GinContext)
	LoginAuth              func(*appcontext.GinContext)
	RefreshAuth            func(*appcontext.GinContext)
	LogoutAuth             func(*appcontext.GinContext)
	GetAssets              func(*appcontext.GinContext)
	GetAsset               func(*appcontext.GinContext)
	CreateAsset            func(*appcontext.GinContext)
	UpdateAsset            func(*appcontext.GinContext)
	DeleteAsset            func(*appcontext.GinContext)
	MatchAssetCPEAndAttach func(*appcontext.GinContext)
	TestAIProvider         func(*appcontext.GinContext)
	SendAIMessage          func(*appcontext.GinContext)
	AssignVulnerability    func(*appcontext.GinContext)
	RemoveVulnerability    func(*appcontext.GinContext)
	GetVulnerabilities     func(*appcontext.GinContext)
	GetVulnerability       func(*appcontext.GinContext)
	CreateVulnerability    func(*appcontext.GinContext)
	UpdateVulnerability    func(*appcontext.GinContext)
	DeleteVulnerability    func(*appcontext.GinContext)
	LookupCVE              func(*appcontext.GinContext)
}

// RegisterRoutes centralizes all route registrations for the application.
func RegisterRoutes(router *gin.Engine, database *gorm.DB, jwtManager *sharedjwt.JWTManager, userLookup jwtmiddleware.UserLookup, sessions jwtmiddleware.RefreshSessionLookup, handlers RouteHandlers) {
	router.GET("/api/health", health.Health)
	router.GET("/api/ready", health.Ready(database))

	auth := router.Group("/api/auth")
	auth.Use(ratelimit.AuthRateLimit())
	{
		auth.POST("/register", appcontext.Wrap(handlers.RegisterAuth))
		auth.POST("/login", appcontext.Wrap(handlers.LoginAuth))
		auth.POST("/refresh", appcontext.Wrap(handlers.RefreshAuth))
		auth.POST("/logout", appcontext.Wrap(handlers.LogoutAuth))
	}

	protected := router.Group("/api")
	protected.Use(jwtmiddleware.JWTAuthenticationFilter(jwtManager, userLookup, sessions))
	{
		protected.GET("/assets", appcontext.Wrap(handlers.GetAssets))
		protected.GET("/assets/:id", appcontext.Wrap(handlers.GetAsset))
		protected.POST("/assets", appcontext.Wrap(handlers.CreateAsset))
		protected.PUT("/assets/:id", appcontext.Wrap(handlers.UpdateAsset))
		protected.DELETE("/assets/:id", appcontext.Wrap(handlers.DeleteAsset))

		adminOnly := protected.Group("/")
		adminOnly.Use(permissions.RequireAdmin())
		{
			adminOnly.POST("/assets/:id/vulnerabilities/:vulnerabilityId", appcontext.Wrap(handlers.AssignVulnerability))
			adminOnly.POST("/assets/:id/match-cpe/vulnerabilities", ratelimit.AIRateLimit(), appcontext.Wrap(handlers.MatchAssetCPEAndAttach))
			adminOnly.DELETE("/assets/:id/vulnerabilities/:vulnerabilityId", appcontext.Wrap(handlers.RemoveVulnerability))

			adminOnly.GET("/vulnerabilities", appcontext.Wrap(handlers.GetVulnerabilities))
			adminOnly.GET("/vulnerabilities/:id", appcontext.Wrap(handlers.GetVulnerability))
			adminOnly.POST("/vulnerabilities", appcontext.Wrap(handlers.CreateVulnerability))
			adminOnly.PUT("/vulnerabilities/:id", appcontext.Wrap(handlers.UpdateVulnerability))
			adminOnly.DELETE("/vulnerabilities/:id", appcontext.Wrap(handlers.DeleteVulnerability))

			nvd := adminOnly.Group("/nvd", ratelimit.NVDLookupRateLimit())
			{
				nvd.GET("/cves/:cveId", appcontext.Wrap(handlers.LookupCVE))
			}

			ai := adminOnly.Group("/ai", ratelimit.AIRateLimit())
			{
				ai.GET("/test", appcontext.Wrap(handlers.TestAIProvider))
				ai.POST("/message", appcontext.Wrap(handlers.SendAIMessage))
			}
		}
	}
}
