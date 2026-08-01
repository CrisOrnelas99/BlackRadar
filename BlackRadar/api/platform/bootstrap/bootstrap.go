// Package bootstrap seeds local development data at application startup when enabled.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"blackradar/api/platform/config"
)

var ErrDatabaseRequired = errors.New("bootstrap dev data requires a database connection")

// Run seeds developer bootstrap data when explicitly enabled.
func Run(ctx context.Context, database *gorm.DB, cfg config.Config) error {
	if !cfg.BootstrapDevData {
		return nil
	}

	if !cfg.AllowsBootstrapData() {
		return fmt.Errorf(
			"%w: %q",
			config.ErrBootstrapNotAllowed,
			cfg.Environment,
		)
	}

	if strings.TrimSpace(cfg.BootstrapDevPassword) == "" {
		return fmt.Errorf("%w", config.ErrMissingBootstrapPassword)
	}

	if database == nil {
		return fmt.Errorf("%w", ErrDatabaseRequired)
	}

	return seedDevData(ctx, database, cfg.BootstrapDevPassword)
}
