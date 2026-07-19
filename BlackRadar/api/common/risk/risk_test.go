package risk

import (
	"context"
	"errors"
	"testing"

	"gorm.io/gorm"

	"blackradar/api/model"
)

func TestFromSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		want     string
	}{
		{name: "critical", severity: "CRITICAL", want: "Critical"},
		{name: "high", severity: "High", want: "High"},
		{name: "medium", severity: "medium", want: "Medium"},
		{name: "unknown defaults low", severity: "informational", want: "Low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FromSeverity(tt.severity); got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestFromVulnerabilities(t *testing.T) {
	vulnerabilities := []model.Vulnerability{
		{Severity: "Low"},
		{Severity: "Critical"},
		{Severity: "Medium"},
	}

	if got := FromVulnerabilities(vulnerabilities); got != "Critical" {
		t.Fatalf("expected Critical, got %q", got)
	}
}

func TestPointerFromVulnerabilities(t *testing.T) {
	if got := PointerFromVulnerabilities(nil); got != nil {
		t.Fatalf("expected nil risk pointer for empty vulnerabilities, got %#v", got)
	}

	vulnerabilities := []model.Vulnerability{{Severity: "High"}}
	got := PointerFromVulnerabilities(vulnerabilities)
	if got == nil || *got != "High" {
		t.Fatalf("expected High risk level pointer, got %#v", got)
	}
}

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
		{ID: "asset-1", UserID: "user-1"},
		{ID: "asset-2", UserID: "user-2"},
	}

	var called []assetRow
	loadAssetRows = func(ctx context.Context, database *gorm.DB) ([]assetRow, error) {
		return assets, nil
	}
	runBackfillTransaction = func(ctx context.Context, database *gorm.DB, fn func(tx *gorm.DB) error) error {
		return fn(nil)
	}
	refreshAssetRisk = func(tx *gorm.DB, assetID string, userID string) error {
		called = append(called, assetRow{ID: assetID, UserID: userID})
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
	refreshAssetRisk = func(tx *gorm.DB, assetID string, userID string) error {
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
		return []assetRow{{ID: "asset-1", UserID: "user-1"}}, nil
	}
	runBackfillTransaction = func(ctx context.Context, database *gorm.DB, fn func(tx *gorm.DB) error) error {
		return fn(nil)
	}
	refreshAssetRisk = func(tx *gorm.DB, assetID string, userID string) error {
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
