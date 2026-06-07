package main

import (
	"context"
	"log"
	"time"

	"github.com/gin-gonic/gin"

	"secureops/backend-go/api/config"
	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/controller"
	"secureops/backend-go/api/database"
	"secureops/backend-go/api/middleware"
	"secureops/backend-go/api/repository"
	"secureops/backend-go/api/security"
	"secureops/backend-go/api/service"
)

func main() {
	cfg := config.Load()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gormDB, err := database.Connect(ctx, cfg)
	if err != nil {
		log.Fatalf("database connection failed: %v", err)
	}
	defer func() {
		if err := database.Close(gormDB); err != nil {
			log.Printf("database close failed: %v", err)
		}
	}()

	if err := database.EnsureSchema(ctx, gormDB); err != nil {
		log.Fatalf("database schema setup failed: %v", err)
	}

	jwtService := security.NewJwtService(cfg.JWTSecret, cfg.JWTExpiration)

	userRepository := repository.NewUserRepository(gormDB)
	wafEventRepository := repository.NewWafEventRepository(gormDB)

	restClient := config.RestClientConfig(cfg)
	service.NewAuthService(jwtService)
	service.NewAssetRiskService()
	service.NewAssetService(restClient)
	service.NewVulnerabilityService()

	authController := controller.NewAuthController()
	assetController := controller.NewAssetController()
	vulnerabilityController := controller.NewVulnerabilityController()

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.RequestContext())
	router.Use(middleware.GormMiddleware(gormDB))
	router.Use(config.CorsConfig())
	router.Use(middleware.WafFilter(wafEventRepository))

	router.GET("/api/health", controller.Health)
	router.POST("/api/auth/register", appcontext.Wrap(authController.Register))
	router.POST("/api/auth/login", appcontext.Wrap(authController.Login))

	protected := router.Group("/api")
	protected.Use(config.SecurityConfig(jwtService, userRepository))
	{
		protected.GET("/test/secure", controller.SecureTest)

		protected.GET("/assets", appcontext.Wrap(assetController.GetAssets))
		protected.GET("/assets/:id", appcontext.Wrap(assetController.GetAsset))
		protected.POST("/assets", appcontext.Wrap(assetController.CreateAsset))
		protected.PUT("/assets/:id", appcontext.Wrap(assetController.UpdateAsset))
		protected.DELETE("/assets/:id", appcontext.Wrap(assetController.DeleteAsset))
		protected.POST("/assets/:id/vulnerabilities/:vulnerabilityId", appcontext.Wrap(assetController.AssignVulnerability))
		protected.DELETE("/assets/:id/vulnerabilities/:vulnerabilityId", appcontext.Wrap(assetController.RemoveVulnerability))
		protected.POST("/assets/:id/calculate-risk", appcontext.Wrap(assetController.CalculateRisk))

		protected.GET("/vulnerabilities", appcontext.Wrap(vulnerabilityController.GetVulnerabilities))
		protected.GET("/vulnerabilities/:id", appcontext.Wrap(vulnerabilityController.GetVulnerability))
		protected.POST("/vulnerabilities", appcontext.Wrap(vulnerabilityController.CreateVulnerability))
		protected.PUT("/vulnerabilities/:id", appcontext.Wrap(vulnerabilityController.UpdateVulnerability))
		protected.DELETE("/vulnerabilities/:id", appcontext.Wrap(vulnerabilityController.DeleteVulnerability))
	}

	log.Printf("Go backend running on :%s", cfg.Port)
	if err := router.Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}
