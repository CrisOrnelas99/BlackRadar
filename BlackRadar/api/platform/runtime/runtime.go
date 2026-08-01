// Package runtime wires and starts the HTTP API.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	commonjwt "blackradar/api/common/jwt"
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
	repositoryassetmatch "blackradar/api/repository/asset_match"
	repositoryassetrisk "blackradar/api/repository/asset_risk"
	repositoryassetvulnerability "blackradar/api/repository/asset_vulnerability"
	repositoryaudit "blackradar/api/repository/audit"
	repositoryproviderusage "blackradar/api/repository/provider_usage"
	repositoryuser "blackradar/api/repository/user"
	repositoryvulnerability "blackradar/api/repository/vulnerability"
	serviceai "blackradar/api/service/ai"
	serviceasset "blackradar/api/service/asset"
	serviceassetmatch "blackradar/api/service/asset_match"
	serviceassetrisk "blackradar/api/service/asset_risk"
	serviceassetvulnerability "blackradar/api/service/asset_vulnerability"
	serviceaudit "blackradar/api/service/audit"
	serviceuser "blackradar/api/service/user"
	servicevulnerability "blackradar/api/service/vulnerability"
)

// ErrDatabaseRequired indicates router startup was attempted without a database.
var ErrDatabaseRequired = errors.New("runtime requires a database connection")

// Run loads configuration, prepares dependencies, and starts the API server.
func Run(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	return RunWithConfig(ctx, cfg)
}

// RunWithConfig starts the API using an already loaded configuration.
func RunWithConfig(ctx context.Context, cfg config.Config) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate configuration: %w", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	connectCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	gormDB, err := connectDatabaseWithRetry(connectCtx, cfg)
	if err != nil {
		return fmt.Errorf("database connection failed: %w", err)
	}
	defer func() {
		if err := platformdb.Close(gormDB); err != nil {
			log.Printf("database close failed: %v", err)
		}
	}()

	if err := platformdb.RunMigrations(ctx, gormDB); err != nil {
		return fmt.Errorf("database migration failed: %w", err)
	}
	assetRiskService := serviceassetrisk.NewAssetRiskService(repositoryassetrisk.NewAssetRiskRepository(gormDB))
	if err := assetRiskService.BackfillAssetRiskLevels(ctx); err != nil {
		return fmt.Errorf("asset risk level backfill failed: %w", err)
	}
	if err := bootstrap.Run(ctx, gormDB, cfg); err != nil {
		return fmt.Errorf("bootstrap failed: %w", err)
	}

	engine, err := BuildRouter(cfg, gormDB, logger)
	if err != nil {
		return err
	}

	server := newHTTPServer(engine, cfg)
	log.Printf("Go backend running on %s", server.Addr)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("API server failed: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("API server shutdown failed: %w", err)
		}
		return nil
	}
}

// BuildRouter wires middleware, repositories, services, controllers, and routes.
func BuildRouter(cfg config.Config, gormDB *gorm.DB, logger *slog.Logger) (*gin.Engine, error) {
	if gormDB == nil {
		return nil, ErrDatabaseRequired
	}
	if logger == nil {
		logger = slog.Default()
	}

	jwtManager, err := commonjwt.NewManager(cfg.JWTSecret, cfg.JWTExpiration, cfg.JWTRefreshExpiration, cfg.JWTIssuer, cfg.JWTAudience)
	if err != nil {
		return nil, fmt.Errorf("jwt configuration failed: %w", err)
	}

	userRepository := repositoryuser.NewUserRepository(gormDB)
	assetRepository := repositoryasset.NewAssetRepository(gormDB)
	assetMatchRepository := repositoryassetmatch.NewAssetMatchRepository(gormDB)
	assetVulnerabilityRepository := repositoryassetvulnerability.NewAssetVulnerabilityRepository(gormDB)
	assetRiskRepository := repositoryassetrisk.NewAssetRiskRepository(gormDB)
	refreshSessionRepository := repositoryuser.NewRefreshSessionRepository(gormDB)
	vulnerabilityRepository := repositoryvulnerability.NewVulnerabilityRepository(gormDB)
	auditService := serviceaudit.NewService(repositoryaudit.NewRepository(gormDB))
	var providerQuota repositoryproviderusage.RepositoryInterface = repositoryproviderusage.NewRepository(gormDB)

	userService := serviceuser.NewUserService(jwtManager, userRepository, refreshSessionRepository, auditService)
	nvdClient, err := nvdcveclient.NewClientWithQuota(cfg.NVDAPIBaseURL, cfg.NVDAPIKey, providerQuota)
	if err != nil {
		return nil, fmt.Errorf("nvd client configuration failed: %w", err)
	}
	nvdLookupService := serviceassetmatch.NewNVDLookupService(nvdClient)
	cpeClient, err := nvdcpeclient.NewCPEClientWithQuota(cfg.NVDCPEAPIBaseURL, cfg.NVDAPIKey, providerQuota)
	if err != nil {
		return nil, fmt.Errorf("nvd cpe client configuration failed: %w", err)
	}
	openAIClient, err := openaiexternal.NewClientWithHTTPClientAndQuota(cfg.OpenAIAPIEndpoint, cfg.OpenAIAPIKey, cfg.OpenAIModel, &http.Client{Timeout: cfg.OpenAITimeout}, nil, providerQuota)
	if err != nil {
		return nil, fmt.Errorf("openai client configuration failed: %w", err)
	}

	assetRiskService := serviceassetrisk.NewAssetRiskService(assetRiskRepository).WithAuditService(auditService)
	assetMatchService := serviceassetmatch.NewAssetMatchService(assetMatchRepository, assetVulnerabilityRepository, vulnerabilityRepository, cpeClient, nvdClient, openAIClient, assetRiskService).WithAuditService(auditService)
	assetService := serviceasset.NewAssetService(assetRepository, openAIClient, auditService)
	assetVulnerabilityService := serviceassetvulnerability.NewAssetVulnerabilityService(assetVulnerabilityRepository, vulnerabilityRepository, nvdLookupService, assetRiskService).WithAuditService(auditService)
	vulnerabilityService := servicevulnerability.NewVulnerabilityService(vulnerabilityRepository, assetRiskService).WithAuditService(auditService)

	userController := controlleruser.NewUserController(userService, cfg.IsProduction())
	aiController := controllerai.NewAIController(serviceai.NewAIService(openAIClient))
	assetController := controllerasset.NewAssetController(assetService, assetVulnerabilityService, assetMatchService)
	vulnerabilityController := controllervulnerability.NewVulnerabilityController(vulnerabilityService)
	nvdController := controllernvd.NewNVDController(nvdLookupService)

	engine := gin.New()
	if err := configureTrustedProxies(engine, cfg); err != nil {
		return nil, err
	}
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
		AllowCredentials: true,
		MaxAge:           10 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("cors configuration failed: %w", err)
	}
	engine.Use(corsMiddleware)
	engine.Use(filter.RequestFilter())

	controllerhealth.RegisterRoutes(engine, platformdb.NewReadinessChecker(gormDB))
	controlleruser.RegisterRoutes(engine.Group("/api/auth"), userController)

	authenticationMiddleware, err := jwtmiddleware.Authentication(jwtManager, userRepository, refreshSessionRepository)
	if err != nil {
		return nil, fmt.Errorf("jwt middleware configuration failed: %w", err)
	}
	protected := engine.Group("/api")
	protected.Use(authenticationMiddleware)
	adminOnly := protected.Group("")
	adminOnly.Use(permissions.RequireAdmin())

	controllerasset.RegisterRoutes(protected, adminOnly, assetController)
	controllervulnerability.RegisterRoutes(adminOnly, vulnerabilityController)
	controllernvd.RegisterRoutes(adminOnly, nvdController)
	controllerai.RegisterRoutes(adminOnly, aiController)

	return engine, nil
}
