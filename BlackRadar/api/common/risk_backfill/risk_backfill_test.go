// Package risk_backfill verifies the startup backfill orchestration.
package risk_backfill

import (
	"context"
	"errors"
	"testing"

	"gorm.io/gorm"
)

func TestBackfillAssetRiskLevels(t *testing.T) {
	originalLoadAssetRows := loadAssetRows
	originalRunBackfillTransaction := runBackfillTransaction
	originalRefreshAssetRisk := refreshAssetRisk
	t.Cleanup(func() {
		loadAssetRows = originalLoadAssetRows
		runBackfillTransaction = originalRunBackfillTransaction
		refreshAssetRisk = originalRefreshAssetRisk
	})

	assets := []assetRow{
		{ID: "asset-1", OrganizationID: "org-1"},
		{ID: "asset-2", OrganizationID: "org-2"},
	}

	var called []assetRow
	loadAssetRows = func(ctx context.Context, database *gorm.DB) ([]assetRow, error) {
		return assets, nil
	}
	runBackfillTransaction = func(ctx context.Context, database *gorm.DB, fn func(tx *gorm.DB) error) error {
		return fn(nil)
	}
	refreshAssetRisk = func(tx *gorm.DB, assetID string, organizationID string) error {
		called = append(called, assetRow{ID: assetID, OrganizationID: organizationID})
		return nil
	}

	if err := BackfillAssetRiskLevels(context.Background(), &gorm.DB{}); err != nil {
		t.Fatalf("expected backfill to succeed, got %v", err)
	}

	if len(called) != len(assets) {
		t.Fatalf("expected %d refresh calls, got %d", len(assets), len(called))
	}
	for i := range assets {
		if called[i] != assets[i] {
			t.Fatalf("expected refresh call %d to be %#v, got %#v", i, assets[i], called[i])
		}
	}
}

func TestBackfillAssetRiskLevelsReturnsLoadError(t *testing.T) {
	originalLoadAssetRows := loadAssetRows
	originalRunBackfillTransaction := runBackfillTransaction
	originalRefreshAssetRisk := refreshAssetRisk
	t.Cleanup(func() {
		loadAssetRows = originalLoadAssetRows
		runBackfillTransaction = originalRunBackfillTransaction
		refreshAssetRisk = originalRefreshAssetRisk
	})

	expectedErr := errors.New("load failed")
	loadAssetRows = func(ctx context.Context, database *gorm.DB) ([]assetRow, error) {
		return nil, expectedErr
	}
	runBackfillTransaction = func(ctx context.Context, database *gorm.DB, fn func(tx *gorm.DB) error) error {
		t.Fatal("transaction should not run when loading assets fails")
		return nil
	}
	refreshAssetRisk = func(tx *gorm.DB, assetID string, organizationID string) error {
		t.Fatal("refresh should not run when loading assets fails")
		return nil
	}

	err := BackfillAssetRiskLevels(context.Background(), &gorm.DB{})
	if !errors.Is(err, ErrLoadAssetsFailed) {
		t.Fatalf("expected load sentinel error, got %v", err)
	}
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected load cause %v, got %v", expectedErr, err)
	}
}

func TestBackfillAssetRiskLevelsReturnsRefreshError(t *testing.T) {
	originalLoadAssetRows := loadAssetRows
	originalRunBackfillTransaction := runBackfillTransaction
	originalRefreshAssetRisk := refreshAssetRisk
	t.Cleanup(func() {
		loadAssetRows = originalLoadAssetRows
		runBackfillTransaction = originalRunBackfillTransaction
		refreshAssetRisk = originalRefreshAssetRisk
	})

	expectedErr := errors.New("refresh failed")
	loadAssetRows = func(ctx context.Context, database *gorm.DB) ([]assetRow, error) {
		return []assetRow{{ID: "asset-1", OrganizationID: "org-1"}}, nil
	}
	runBackfillTransaction = func(ctx context.Context, database *gorm.DB, fn func(tx *gorm.DB) error) error {
		return fn(nil)
	}
	refreshAssetRisk = func(tx *gorm.DB, assetID string, organizationID string) error {
		return expectedErr
	}

	err := BackfillAssetRiskLevels(context.Background(), &gorm.DB{})
	if !errors.Is(err, ErrRefreshFailed) {
		t.Fatalf("expected refresh sentinel error, got %v", err)
	}
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected refresh cause %v, got %v", expectedErr, err)
	}
}

func TestBackfillAssetRiskLevelsRejectsMissingDatabase(t *testing.T) {
	err := BackfillAssetRiskLevels(context.Background(), nil)
	if !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected database required error, got %v", err)
	}
}
