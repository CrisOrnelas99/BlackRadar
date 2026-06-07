package controller

import (
	"log"

	"github.com/gin-gonic/gin"

	"secureops/backend-go/api/config"
	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/middleware"
	"secureops/backend-go/api/security"
)

// RegisterRoutes centralizes all route registrations for the application.
func RegisterRoutes(router *gin.Engine, jwtService *security.JwtService, userLookup middleware.UserLookup, authController *AuthController, assetController *AssetController, vulnerabilityController *VulnerabilityController) {
	router.GET("/api/health", Health)
	router.POST("/api/auth/register", appcontext.Wrap(authController.Register))
	router.POST("/api/auth/login", appcontext.Wrap(authController.Login))

	protected := router.Group("/api")
	protected.Use(config.SecurityConfig(jwtService, userLookup))
	{
		protected.GET("/test/secure", SecureTest)

		protected.GET("/assets", appcontext.Wrap(assetController.GetAssets))
		protected.GET("/assets/:id", appcontext.Wrap(assetController.GetAsset))
		protected.POST("/assets", appcontext.Wrap(assetController.CreateAsset))
		protected.PUT("/assets/:id", appcontext.Wrap(assetController.UpdateAsset))
		protected.DELETE("/assets/:id", appcontext.Wrap(assetController.DeleteAsset))
		protected.POST("/assets/:id/vulnerabilities/:vulnerabilityId", appcontext.Wrap(assetController.AssignVulnerability))
		protected.DELETE("/assets/:id/vulnerabilities/:vulnerabilityId", appcontext.Wrap(assetController.RemoveVulnerability))

		protected.GET("/vulnerabilities", appcontext.Wrap(vulnerabilityController.GetVulnerabilities))
		protected.GET("/vulnerabilities/:id", appcontext.Wrap(vulnerabilityController.GetVulnerability))
		protected.POST("/vulnerabilities", appcontext.Wrap(vulnerabilityController.CreateVulnerability))
		protected.PUT("/vulnerabilities/:id", appcontext.Wrap(vulnerabilityController.UpdateVulnerability))
		protected.DELETE("/vulnerabilities/:id", appcontext.Wrap(vulnerabilityController.DeleteVulnerability))
	}

	printRegisteredRoutes(router)
}

func printRegisteredRoutes(router *gin.Engine) {
	routes := router.Routes()
	log.Println("Registered routes:")
	for _, r := range routes {
		log.Printf("%s %s -> %s", r.Method, r.Path, r.Handler)
	}
}
