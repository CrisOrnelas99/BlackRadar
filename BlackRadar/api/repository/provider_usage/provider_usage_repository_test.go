// Package providerusage verifies durable provider quota persistence.
package providerusage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	providerquota "blackradar/api/external/provider_quota"
	"blackradar/api/model"
	platformdb "blackradar/api/platform/db"
)

func TestRepositoryReserveRejectsInvalidConfiguration(t *testing.T) {
	repository := NewRepository(nil)

	err := repository.Reserve(context.Background(), providerquota.OpenAI, time.Now(), 1, time.Minute)
	if !errors.Is(err, providerquota.ErrUnavailable) {
		t.Fatalf("expected unavailable quota error, got %v", err)
	}
	if !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected database-required repository error, got %v", err)
	}
}

func TestRepositoryReserveEnforcesAtomicQuotaIntegration(t *testing.T) {
	databaseURL := os.Getenv("INTEGRATION_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set INTEGRATION_DATABASE_URL to run PostgreSQL integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	database, err := gorm.Open(postgres.Open(databaseURL), &gorm.Config{})
	if err != nil {
		t.Fatalf("open integration database: %v", err)
	}
	if err := platformdb.RunMigrations(ctx, database); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	provider := fmt.Sprintf("test-%d", time.Now().UnixNano())
	repository := NewRepository(database)
	defer database.Unscoped().Where("provider = ?", provider).Delete(&model.ProviderUsageBucket{})

	window := time.Hour
	for attempt := 1; attempt <= 2; attempt++ {
		if err := repository.Reserve(ctx, provider, time.Now(), 2, window); err != nil {
			t.Fatalf("expected reservation %d to succeed, got %v", attempt, err)
		}
	}

	err = repository.Reserve(ctx, provider, time.Now(), 2, window)
	if !errors.Is(err, providerquota.ErrExceeded) {
		t.Fatalf("expected quota exhaustion after two reservations, got %v", err)
	}
}
