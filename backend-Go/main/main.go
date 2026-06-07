package main

import (
	"context"
	"log"
	"time"

	"github.com/gin-gonic/gin"

	"secureops/backend-go/api/config"
	"secureops/backend-go/api/controller"
	"secureops/backend-go/api/middleware"
	"secureops/backend-go/api/repository"
	"secureops/backend-go/api/security"
	"secureops/backend-go/api/service"
	"secureops/backend-go/api/utils"
)

func main() {
	cfg := config.Load()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gormDB, err := utils.Connect(ctx, cfg)
	if err != nil {
		log.Fatalf("database connection failed: %v", err)
	}
	defer func() {
		if err := utils.Close(gormDB); err != nil {
			log.Printf("database close failed: %v", err)
		}
	}()

	if err := utils.RunMigrations(ctx, gormDB); err != nil {
		log.Fatalf("database migration failed: %v", err)
	}

	jwtService := security.NewJwtService(cfg.JWTSecret, cfg.JWTExpiration)

	userRepository := repository.NewUserRepository(gormDB)
	assetRepository := repository.NewAssetRepository(gormDB)
	vulnerabilityRepository := repository.NewVulnerabilityRepository(gormDB)
	authService := service.NewAuthService(jwtService, userRepository)
	assetService := service.NewAssetService(assetRepository)
	vulnerabilityService := service.NewVulnerabilityService(vulnerabilityRepository)

	authController := controller.NewAuthController(authService)
	assetController := controller.NewAssetController(assetService)
	vulnerabilityController := controller.NewVulnerabilityController(vulnerabilityService)

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.RequestContext())
	router.Use(middleware.GormMiddleware(gormDB))
	router.Use(config.CorsConfig())
	router.Use(middleware.RequestFilter())
	// Register all routes centrally in the controller package
	controller.RegisterRoutes(router, jwtService, userRepository, authController, assetController, vulnerabilityController)

	log.Printf("Go backend running on :%s", cfg.Port)
	if err := router.Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}
