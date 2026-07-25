package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	commonjwt "blackradar/api/common/jwt"
	commonrisk "blackradar/api/common/risk"
	controllerai "blackradar/api/controller/ai"
	controllerasset "blackradar/api/controller/asset"
	controllerhealth "blackradar/api/controller/health"
	controllernvd "blackradar/api/controller/nvd"
	controlleruser "blackradar/api/controller/user"
	controllervulnerability "blackradar/api/controller/vulnerability"
	nvdcpeclient "blackradar/api/external/nvd_cpe"
	nvdcveclient "blackradar/api/external/nvd_cve"
	openaiexternal "blackradar/api/external/openai"
	contextmiddleware "blackradar/api/middleware/context"
	"blackradar/api/middleware/cors"
	"blackradar/api/middleware/filter"
	gormmiddleware "blackradar/api/middleware/gorm"
	jwtmiddleware "blackradar/api/middleware/jwt"
	"blackradar/api/middleware/permissions"
	securityheaders "blackradar/api/middleware/security_headers"
	"blackradar/api/platform/bootstrap"
	"blackradar/api/platform/config"
	platformdb "blackradar/api/platform/db"
	repositoryasset "blackradar/api/repository/asset"
	repositoryuser "blackradar/api/repository/user"
	repositoryvulnerability "blackradar/api/repository/vulnerability"
	serviceasset "blackradar/api/service/asset"
	servicematch "blackradar/api/service/match"
	serviceuser "blackradar/api/service/user"
	servicevulnerability "blackradar/api/service/vulnerability"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load configuration: %v", err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	gormDB, err := connectDatabaseWithRetry(ctx, cfg)
	if err != nil {
		log.Fatalf("database connection failed: %v", err)
	}
	defer func() {
		if err := platformdb.Close(gormDB); err != nil {
			log.Printf("database close failed: %v", err)
		}
	}()

	if err := platformdb.RunMigrations(ctx, gormDB); err != nil {
		log.Fatalf("database migration failed: %v", err)
	}
	if err := commonrisk.BackfillAssetRiskLevels(ctx, gormDB); err != nil {
		log.Fatalf("asset risk level backfill failed: %v", err)
	}
	if err := bootstrap.Run(ctx, gormDB, cfg); err != nil {
		log.Fatalf("bootstrap failed: %v", err)
	}

	jwtManager, err := commonjwt.NewManager(cfg.JWTSecret, cfg.JWTExpiration, cfg.JWTRefreshExpiration, cfg.JWTIssuer, cfg.JWTAudience)
	if err != nil {
		log.Fatalf("jwt configuration failed: %v", err)
	}

	userRepository := repositoryuser.NewUserRepository(gormDB)
	assetRepository := repositoryasset.NewAssetRepository(gormDB)
	refreshSessionRepository := repositoryuser.NewRefreshSessionRepository(gormDB)
	vulnerabilityRepository := repositoryvulnerability.NewVulnerabilityRepository(gormDB)
	userService := serviceuser.NewUserService(jwtManager, userRepository, refreshSessionRepository)
	nvdClient, err := nvdcveclient.NewClient(cfg.NVDAPIBaseURL, cfg.NVDAPIKey)
	if err != nil {
		log.Fatalf("nvd client configuration failed: %v", err)
	}
	nvdLookupService := servicematch.NewNVDLookupService(nvdClient)
	cpeClient, err := nvdcpeclient.NewCPEClient(cfg.NVDCPEAPIBaseURL, cfg.NVDAPIKey)
	if err != nil {
		log.Fatalf("nvd cpe client configuration failed: %v", err)
	}
	openAIClient, err := openaiexternal.NewClientWithHTTPClient(cfg.OpenAIAPIEndpoint, cfg.OpenAIAPIKey, cfg.OpenAIModel, &http.Client{Timeout: cfg.OpenAITimeout}, nil)
	if err != nil {
		log.Fatalf("openai client configuration failed: %v", err)
	}
	assetMatchService := servicematch.NewAssetMatchService(assetRepository, vulnerabilityRepository, cpeClient, nvdClient, openAIClient)
	assetService := serviceasset.NewAssetService(assetRepository, vulnerabilityRepository, nvdLookupService, openAIClient)
	vulnerabilityService := servicevulnerability.NewVulnerabilityService(vulnerabilityRepository)

	userController := controlleruser.NewUserController(userService)
	aiController := controllerai.NewAIController(openAIClient)
	assetController := controllerasset.NewAssetController(assetService, assetMatchService)
	vulnerabilityController := controllervulnerability.NewVulnerabilityController(vulnerabilityService)
	nvdController := controllernvd.NewNVDController(nvdLookupService)

	engine := gin.New()
	engine.Use(gin.Recovery())
	engine.Use(contextmiddleware.RequestContext(logger))
	engine.Use(securityheaders.SecurityHeaders(securityheaders.Config{
		EnableHSTS:          cfg.IsProduction(),
		HSTSMaxAge:          31536000,
		HSTSIncludeDomains:  true,
		TrustForwardedProto: cfg.IsProduction(),
	}))
	engine.Use(gormmiddleware.RequestDatabase(gormDB))
	corsMiddleware, err := cors.New(cors.Config{
		AllowedOrigins:   cfg.CorsAllowedOrigins,
		AllowedMethods:   []string{http.MethodDelete, http.MethodGet, http.MethodOptions, http.MethodPatch, http.MethodPost, http.MethodPut},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		ExposedHeaders:   []string{"X-Request-ID"},
		AllowCredentials: false,
		MaxAge:           10 * time.Minute,
	})
	if err != nil {
		log.Fatalf("cors configuration failed: %v", err)
	}
	engine.Use(corsMiddleware)
	engine.Use(filter.RequestFilter())

	controllerhealth.RegisterRoutes(engine, gormDB)
	controlleruser.RegisterRoutes(engine.Group("/api/auth"), userController)

	authenticationMiddleware, err := jwtmiddleware.Authentication(jwtManager, userRepository, refreshSessionRepository)
	if err != nil {
		log.Fatalf("jwt middleware configuration failed: %v", err)
	}
	protected := engine.Group("/api")
	protected.Use(authenticationMiddleware)
	adminOnly := protected.Group("")
	adminOnly.Use(permissions.RequireAdmin())

	controllerasset.RegisterRoutes(protected, adminOnly, assetController)
	controllervulnerability.RegisterRoutes(adminOnly, vulnerabilityController)
	controllernvd.RegisterRoutes(adminOnly, nvdController)
	controllerai.RegisterRoutes(adminOnly, aiController)

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
		database, err := platformdb.Connect(ctx, cfg)
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
