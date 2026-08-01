package runtime

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"blackradar/api/platform/config"
	platformdb "blackradar/api/platform/db"
)

const (
	databaseConnectAttempts = 15
	databaseConnectDelay    = 2 * time.Second

	apiReadHeaderTimeout = 10 * time.Second
	apiReadTimeout       = 30 * time.Second
	apiWriteTimeout      = 30 * time.Second
	apiIdleTimeout       = 120 * time.Second
	apiMaxHeaderBytes    = 16 * 1024
)

// newHTTPServer creates the API server with explicit slow-client protections.
func newHTTPServer(handler http.Handler, cfg config.Config) *http.Server {
	return &http.Server{
		Addr:              serverAddress(cfg),
		Handler:           handler,
		ReadHeaderTimeout: apiReadHeaderTimeout,
		ReadTimeout:       apiReadTimeout,
		WriteTimeout:      apiWriteTimeout,
		IdleTimeout:       apiIdleTimeout,
		MaxHeaderBytes:    apiMaxHeaderBytes,
	}
}

// configureTrustedProxies applies the operator-defined proxy trust boundary.
func configureTrustedProxies(engine *gin.Engine, cfg config.Config) error {
	if err := engine.SetTrustedProxies(cfg.TrustedProxyCIDRs); err != nil {
		return fmt.Errorf("trusted proxy configuration failed: %w", err)
	}

	return nil
}

// connectDatabaseWithRetry opens the database, retrying during dependent service startup.
func connectDatabaseWithRetry(
	ctx context.Context,
	cfg config.Config,
) (*gorm.DB, error) {
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

// serverAddress returns the TCP listen address for the configured API port.
func serverAddress(cfg config.Config) string {
	return ":" + cfg.Port
}
