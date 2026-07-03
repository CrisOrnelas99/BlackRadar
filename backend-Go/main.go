package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"secureops/backend-go/api/config"
	"secureops/backend-go/api/controller"
	controllerai "secureops/backend-go/api/controller/ai"
	controllerasset "secureops/backend-go/api/controller/asset"
	controllerauth "secureops/backend-go/api/controller/auth"
	controllernvd "secureops/backend-go/api/controller/nvd"
	controllervulnerability "secureops/backend-go/api/controller/vulnerability"
	nvdexternal "secureops/backend-go/api/external/nvd"
	openaiexternal "secureops/backend-go/api/external/openai"
	"secureops/backend-go/api/middleware"
	repositoryasset "secureops/backend-go/api/repository/asset"
	repositoryorganization "secureops/backend-go/api/repository/organization"
	repositoryrefreshsession "secureops/backend-go/api/repository/refresh_session"
	repositoryuser "secureops/backend-go/api/repository/user"
	repositoryvulnerability "secureops/backend-go/api/repository/vulnerability"
	"secureops/backend-go/api/security"
	serviceasset "secureops/backend-go/api/service/asset"
	serviceauth "secureops/backend-go/api/service/auth"
	servicenvd "secureops/backend-go/api/service/nvd"
	servicevulnerability "secureops/backend-go/api/service/vulnerability"
	"secureops/backend-go/api/utils"
	"secureops/backend-go/bootstrap"
)

func main() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("configuration validation failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	gormDB, err := connectDatabaseWithRetry(ctx, cfg)
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
	if err := utils.BackfillAssetRiskLevels(ctx, gormDB); err != nil {
		log.Fatalf("asset risk level backfill failed: %v", err)
	}
	if err := bootstrap.Run(ctx, gormDB, cfg); err != nil {
		log.Fatalf("bootstrap failed: %v", err)
	}

	jwtManager := security.NewJWTManager(cfg.JWTSecret, cfg.JWTExpiration, cfg.JWTRefreshExpiration, cfg.JWTIssuer, cfg.JWTAudience)

	userRepository := repositoryuser.NewUserRepository(gormDB)
	organizationRepository := repositoryorganization.NewOrganizationRepository(gormDB)
	assetRepository := repositoryasset.NewAssetRepository(gormDB)
	refreshSessionRepository := repositoryrefreshsession.NewRefreshSessionRepository(gormDB)
	vulnerabilityRepository := repositoryvulnerability.NewVulnerabilityRepository(gormDB)
	authService := serviceauth.NewAuthService(jwtManager, organizationRepository, userRepository, refreshSessionRepository)
	nvdClient, err := nvdexternal.NewClient(cfg.NVDAPIBaseURL, cfg.NVDAPIKey)
	if err != nil {
		log.Fatalf("nvd client configuration failed: %v", err)
	}
	nvdLookupService := servicenvd.NewNVDLookupService(nvdClient)
	cpeClient, err := nvdexternal.NewCPEClient(cfg.NVDCPEAPIBaseURL, cfg.NVDAPIKey)
	if err != nil {
		log.Fatalf("nvd cpe client configuration failed: %v", err)
	}
	openAIClient, err := openaiexternal.NewClientWithHTTPClient(cfg.OpenAIAPIEndpoint, cfg.OpenAIAPIKey, cfg.OpenAIModel, &http.Client{Timeout: cfg.OpenAITimeout})
	if err != nil {
		log.Fatalf("openai client configuration failed: %v", err)
	}
	assetMatchService := serviceasset.NewAssetMatchService(assetRepository, vulnerabilityRepository, cpeClient, nvdClient, openAIClient)
	assetService := serviceasset.NewAssetService(assetRepository, vulnerabilityRepository, nvdLookupService, openAIClient)
	vulnerabilityService := servicevulnerability.NewVulnerabilityService(vulnerabilityRepository)

	authController := controllerauth.NewAuthController(authService)
	aiController := controllerai.NewAIController(openAIClient)
	assetController := controllerasset.NewAssetController(assetService, assetMatchService)
	vulnerabilityController := controllervulnerability.NewVulnerabilityController(vulnerabilityService)
	nvdController := controllernvd.NewNVDController(nvdLookupService)

	engine := gin.New()
	engine.Use(gin.Recovery())
	engine.Use(middleware.RequestContext())
	engine.Use(middleware.SecurityHeaders())
	engine.Use(middleware.GormMiddleware(gormDB))
	engine.Use(middleware.Cors(cfg.CorsAllowedOrigin))
	engine.Use(middleware.RequestFilter())
	// Register all routes centrally in the controller package
	controller.RegisterRoutes(engine, jwtManager, userRepository, refreshSessionRepository, controller.RouteHandlers{
		RegisterAuth:           authController.Register,
		LoginAuth:              authController.Login,
		RefreshAuth:            authController.Refresh,
		LogoutAuth:             authController.Logout,
		GetAssets:              assetController.GetAssets,
		GetAsset:               assetController.GetAsset,
		CreateAsset:            assetController.CreateAsset,
		UpdateAsset:            assetController.UpdateAsset,
		DeleteAsset:            assetController.DeleteAsset,
		MatchAssetCPEAndAttach: assetController.MatchAssetCPEAndAttachVulnerabilities,
		TestAIProvider:         aiController.TestProvider,
		SendAIMessage:          aiController.SendMessage,
		AssignVulnerability:    assetController.AssignVulnerability,
		RemoveVulnerability:    assetController.RemoveVulnerability,
		GetVulnerabilities:     vulnerabilityController.GetVulnerabilities,
		GetVulnerability:       vulnerabilityController.GetVulnerability,
		CreateVulnerability:    vulnerabilityController.CreateVulnerability,
		UpdateVulnerability:    vulnerabilityController.UpdateVulnerability,
		DeleteVulnerability:    vulnerabilityController.DeleteVulnerability,
		LookupCVE:              nvdController.LookupCVE,
	})

	log.Printf("Go backend running on :%s", cfg.Port)
	if err := engine.Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}

const (
	databaseConnectAttempts = 15
	databaseConnectDelay    = 2 * time.Second
)

func connectDatabaseWithRetry(ctx context.Context, cfg config.Config) (*gorm.DB, error) {
	var lastErr error

	for attempt := 1; attempt <= databaseConnectAttempts; attempt++ {
		database, err := utils.Connect(ctx, cfg)
		if err == nil {
			return database, nil
		}

		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		log.Printf("database connection attempt %d/%d failed: %v", attempt, databaseConnectAttempts, err)
		if attempt < databaseConnectAttempts {
			time.Sleep(databaseConnectDelay)
		}
	}

	return nil, fmt.Errorf("connect database after %d attempts: %w", databaseConnectAttempts, lastErr)
}
