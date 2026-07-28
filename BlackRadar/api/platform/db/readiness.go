package db

import (
	"context"

	"gorm.io/gorm"
)

// ReadinessChecker adapts the application database to the health boundary.
type ReadinessChecker struct {
	database *gorm.DB
}

// NewReadinessChecker creates a database readiness checker.
func NewReadinessChecker(database *gorm.DB) *ReadinessChecker {
	return &ReadinessChecker{database: database}
}

// Ping verifies that the database connection is available.
func (r *ReadinessChecker) Ping(ctx context.Context) error {
	if r == nil || r.database == nil {
		return ErrConnectionFailure
	}

	sqlDatabase, err := r.database.DB()
	if err != nil {
		return err
	}

	return sqlDatabase.PingContext(ctx)
}
