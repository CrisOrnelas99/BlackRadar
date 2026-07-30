// Package providerusage persists durable outbound-provider usage buckets.
package providerusage

import (
	"context"
	"fmt"
	"strings"
	"time"

	providerquota "blackradar/api/external/provider_quota"

	"gorm.io/gorm"
)

// Repository persists shared provider quota reservations.
type Repository struct {
	db *gorm.DB
}

// NewRepository creates a provider usage repository backed by the supplied database.
func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// Reserve atomically records one request for a provider within its quota window.
func (r *Repository) Reserve(ctx context.Context, provider string, now time.Time, limit int, window time.Duration) error {
	provider = strings.TrimSpace(provider)
	if r == nil || r.db == nil {
		return fmt.Errorf("%w: %w", providerquota.ErrUnavailable, ErrDatabaseRequired)
	}
	if provider == "" || limit <= 0 || window <= 0 {
		return fmt.Errorf("%w: %w", providerquota.ErrUnavailable, ErrInvalidConfiguration)
	}

	windowStart := now.UTC().Truncate(window)
	var reservation struct {
		RequestCount int
	}
	err := r.db.WithContext(ctx).Raw(`
		INSERT INTO provider_usage_buckets
			(id, provider, window_start, request_count, created_at, updated_at)
		VALUES
			(gen_random_uuid(), ?, ?, 1, NOW(), NOW())
		ON CONFLICT (provider, window_start) DO UPDATE
		SET request_count = provider_usage_buckets.request_count + 1,
			updated_at = NOW()
		WHERE provider_usage_buckets.request_count < ?
		RETURNING request_count
	`, provider, windowStart, limit).Scan(&reservation).Error
	if err != nil {
		return fmt.Errorf("%w: %w: reserve provider quota: %w", providerquota.ErrUnavailable, ErrPersistenceFailure, err)
	}
	if reservation.RequestCount == 0 {
		return providerquota.ErrExceeded
	}
	return nil
}

var _ RepositoryInterface = (*Repository)(nil)
