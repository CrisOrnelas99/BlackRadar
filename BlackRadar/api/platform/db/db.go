// Package db provides database connection, migration, transaction, and error translation helpers.
package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"blackradar/api/platform/config"
)

const (
	defaultMaxOpenConnections = 25
	defaultMaxIdleConnections = 10
	defaultConnectionLifetime = 30 * time.Minute
	defaultConnectionIdleTime = 5 * time.Minute
)

var (
	ErrForeignKeyViolation      = errors.New("foreign key violation")
	ErrCheckConstraintViolation = errors.New("check constraint violation")
	ErrUniqueViolation          = errors.New("unique violation")
)

// Connect opens and verifies the application database connection.
func Connect(ctx context.Context, cfg config.Config) (*gorm.DB, error) {
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("connect database: database URL is required")
	}

	database, err := gorm.Open(
		postgres.Open(cfg.DatabaseURL),
		&gorm.Config{
			Logger: logger.Default.LogMode(logger.Warn),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("connect database: open connection: %w", err)
	}

	sqlDatabase, err := database.DB()
	if err != nil {
		return nil, fmt.Errorf(
			"connect database: access connection pool: %w",
			err,
		)
	}

	sqlDatabase.SetMaxOpenConns(defaultMaxOpenConnections)
	sqlDatabase.SetMaxIdleConns(defaultMaxIdleConnections)
	sqlDatabase.SetConnMaxLifetime(defaultConnectionLifetime)
	sqlDatabase.SetConnMaxIdleTime(defaultConnectionIdleTime)

	if err := sqlDatabase.PingContext(ctx); err != nil {
		_ = sqlDatabase.Close()
		return nil, fmt.Errorf("connect database: ping database: %w", err)
	}

	return database, nil
}

// Close closes the underlying SQL connection pool.
func Close(database *gorm.DB) error {
	if database == nil {
		return nil
	}

	sqlDatabase, err := database.DB()
	if err != nil {
		return fmt.Errorf("close database: access connection pool: %w", err)
	}

	if err := sqlDatabase.Close(); err != nil {
		return fmt.Errorf("close database: %w", err)
	}

	return nil
}

// TranslateDatabaseError maps known PostgreSQL constraint errors to shared
// sentinel errors while preserving the original driver error in the chain.
func TranslateDatabaseError(err error) error {
	switch {
	case err == nil:
		return nil
	case isPostgresError(err, "23503"):
		return fmt.Errorf("%w: %w", ErrForeignKeyViolation, err)
	case isPostgresError(err, "23514"):
		return fmt.Errorf("%w: %w", ErrCheckConstraintViolation, err)
	case isPostgresError(err, "23505"):
		return fmt.Errorf("%w: %w", ErrUniqueViolation, err)
	default:
		return err
	}
}

// IsPrimaryKeyViolation reports whether err is a PostgreSQL unique-violation on
// a known primary-key constraint used by application-generated identifiers.
func IsPrimaryKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return false
	}

	switch pgErr.ConstraintName {
	case "assets_pkey",
		"users_pkey",
		"organizations_pkey",
		"vulnerabilities_pkey",
		"asset_assessments_pkey":
		return true
	default:
		return false
	}
}

// WithinTransaction executes an operation inside a GORM transaction.
//
// Returning an error from operation rolls the transaction back. Returning nil
// commits the transaction.
func WithinTransaction(ctx context.Context, database *gorm.DB, operation func(tx *gorm.DB) error) error {
	if database == nil {
		return fmt.Errorf("database transaction: database is required")
	}
	if operation == nil {
		return fmt.Errorf("database transaction: operation is required")
	}

	if err := database.WithContext(ctx).Transaction(operation); err != nil {
		return fmt.Errorf("database transaction: %w", err)
	}

	return nil
}

// isPostgresError reports whether err is a pgx error with the expected SQLSTATE code.
func isPostgresError(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}
