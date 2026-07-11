package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"blackradar/api/bootstrap"
	"blackradar/api/config"
	"blackradar/api/controller"
	controllerai "blackradar/api/controller/ai"
	controllerasset "blackradar/api/controller/asset"
	controllerauth "blackradar/api/controller/auth"
	controllernvd "blackradar/api/controller/nvd"
	controllervulnerability "blackradar/api/controller/vulnerability"
	nvdcpeclient "blackradar/api/external/nvd_cpe"
	nvdcveclient "blackradar/api/external/nvd_cve"
	openaiexternal "blackradar/api/external/openai"
	contextmiddleware "blackradar/api/middleware/context"
	"blackradar/api/middleware/cors"
	"blackradar/api/middleware/filter"
	gormmiddleware "blackradar/api/middleware/gorm"
	securityheaders "blackradar/api/middleware/security_headers"
	repositoryasset "blackradar/api/repository/asset"
	repositoryorganization "blackradar/api/repository/organization"
	repositoryrefreshsession "blackradar/api/repository/refresh_session"
	repositoryuser "blackradar/api/repository/user"
	repositoryvulnerability "blackradar/api/repository/vulnerability"
	serviceasset "blackradar/api/service/asset"
	serviceauth "blackradar/api/service/auth"
	servicenvd "blackradar/api/service/nvd"
	servicevulnerability "blackradar/api/service/vulnerability"
	shareddb "blackradar/api/shared/db"
	sharedjwt "blackradar/api/shared/jwt"
	sharedriskbackfill "blackradar/api/shared/risk_backfill"
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
		if err := shareddb.Close(gormDB); err != nil {
			log.Printf("database close failed: %v", err)
		}
	}()

	if err := shareddb.RunMigrations(ctx, gormDB); err != nil {
		log.Fatalf("database migration failed: %v", err)
	}
	if err := sharedriskbackfill.BackfillAssetRiskLevels(ctx, gormDB); err != nil {
		log.Fatalf("asset risk level backfill failed: %v", err)
	}
	if err := bootstrap.Run(ctx, gormDB, cfg); err != nil {
		log.Fatalf("bootstrap failed: %v", err)
	}

	jwtManager := sharedjwt.NewJWTManager(cfg.JWTSecret, cfg.JWTExpiration, cfg.JWTRefreshExpiration, cfg.JWTIssuer, cfg.JWTAudience)

	userRepository := repositoryuser.NewUserRepository(gormDB)
	organizationRepository := repositoryorganization.NewOrganizationRepository(gormDB)
	assetRepository := repositoryasset.NewAssetRepository(gormDB)
	refreshSessionRepository := repositoryrefreshsession.NewRefreshSessionRepository(gormDB)
	vulnerabilityRepository := repositoryvulnerability.NewVulnerabilityRepository(gormDB)
	authService := serviceauth.NewAuthService(jwtManager, organizationRepository, userRepository, refreshSessionRepository)
	nvdClient, err := nvdcveclient.NewClient(cfg.NVDAPIBaseURL, cfg.NVDAPIKey)
	if err != nil {
		log.Fatalf("nvd client configuration failed: %v", err)
	}
	nvdLookupService := servicenvd.NewNVDLookupService(nvdClient)
	cpeClient, err := nvdcpeclient.NewCPEClient(cfg.NVDCPEAPIBaseURL, cfg.NVDAPIKey)
	if err != nil {
		log.Fatalf("nvd cpe client configuration failed: %v", err)
	}
	openAIClient, err := openaiexternal.NewClientWithHTTPClient(cfg.OpenAIAPIEndpoint, cfg.OpenAIAPIKey, cfg.OpenAIModel, &http.Client{Timeout: cfg.OpenAITimeout}, nil)
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
	engine.Use(contextmiddleware.RequestContext())
	engine.Use(securityheaders.SecurityHeaders())
	engine.Use(gormmiddleware.GormMiddleware(gormDB))
	engine.Use(cors.Cors(cfg.CorsAllowedOrigins))
	engine.Use(filter.RequestFilter())
	// Register all routes centrally in the controller package
	controller.RegisterRoutes(engine, gormDB, jwtManager, userRepository, refreshSessionRepository, controller.RouteHandlers{
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
		database, err := shareddb.Connect(ctx, cfg)
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
