// Package repository verifies asset repository behavior.
package repository

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"blackradar/api/common/pagination"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

func TestAssetListQueryBuildsScopedFiltersAndOrdering(t *testing.T) {
	database, err := gorm.Open(
		postgres.New(postgres.Config{DSN: "host=localhost user=test dbname=test sslmode=disable", PreferSimpleProtocol: true}),
		&gorm.Config{DryRun: true, DisableAutomaticPing: true},
	)
	if err != nil {
		t.Fatalf("open dry-run database: %v", err)
	}
	vulnerabilityValue := 2
	query := model.AssetListQuery{
		Pagination:         pagination.Request{Page: 2, PageSize: pagination.DefaultPageSize},
		Search:             "server_100%",
		Criticality:        "High",
		Vendor:             "Dell",
		VulnerabilityMode:  model.AssetVulnerabilityFilterAtLeast,
		VulnerabilityValue: &vulnerabilityValue,
		SortField:          model.AssetSortVulnerabilityCount,
		SortDirection:      model.AssetSortDescending,
	}
	userID := "00000000-0000-4000-8000-000000000042"

	sql := database.ToSQL(func(tx *gorm.DB) *gorm.DB {
		filtered := applyAssetListFilters(assetListDatabase(tx, userID), query)
		return filtered.Order(assetListOrder(query)).Order("assets.id ASC").Offset(pagination.DefaultPageSize).Limit(pagination.DefaultPageSize).Find(&[]model.Asset{})
	})

	for _, expected := range []string{
		"assets.user_id",
		"LOWER(assets.name) LIKE",
		"LOWER(assets.criticality)",
		"LOWER(COALESCE(assets.vendor, ''))",
		"COALESCE(asset_vulnerability_counts.vulnerability_count, 0) >= 2",
		"COALESCE(asset_vulnerability_counts.vulnerability_count, 0) DESC",
		"LIMIT 6 OFFSET 6",
	} {
		if !strings.Contains(sql, expected) {
			t.Fatalf("expected SQL to contain %q, got %s", expected, sql)
		}
	}
	if !strings.Contains(sql, `server\_100\%`) {
		t.Fatalf("expected LIKE wildcard characters to be escaped, got %s", sql)
	}
}

func TestAssetSummaryQueryUsesScopedDatabaseAggregates(t *testing.T) {
	database, err := gorm.Open(
		postgres.New(postgres.Config{DSN: "host=localhost user=test dbname=test sslmode=disable", PreferSimpleProtocol: true}),
		&gorm.Config{DryRun: true, DisableAutomaticPing: true},
	)
	if err != nil {
		t.Fatalf("open dry-run database: %v", err)
	}
	userID := "00000000-0000-4000-8000-000000000042"

	sql := database.ToSQL(func(tx *gorm.DB) *gorm.DB {
		return assetSummaryDatabase(tx, userID).Find(&model.AssetSummary{})
	})

	for _, expected := range []string{
		"assets.user_id",
		"unscanned_count",
		"with_vulnerabilities_count",
		"critical_risk_count",
		"asset_vulnerabilities",
	} {
		if !strings.Contains(sql, expected) {
			t.Fatalf("expected summary SQL to contain %q, got %s", expected, sql)
		}
	}
}

// TestAssetRepositoryErrors verifies asset repository errors are storage outcome sentinels.
func TestAssetRepositoryErrors(t *testing.T) {
	err := errors.Join(ErrPersistenceFailure, errors.New("database unavailable"))
	if !errors.Is(err, ErrPersistenceFailure) {
		t.Fatal("expected wrapped persistence failure to match sentinel")
	}
	if errors.Is(err, ErrNotNullViolation) {
		t.Fatal("expected persistence failure to stay distinct from invalid data")
	}
}

// TestAssetRepositoryDatabasePrefersContextDB verifies the context database is preferred.
func TestAssetRepositoryDatabasePrefersContextDB(t *testing.T) {
	fallback := &gorm.DB{}
	repo := NewAssetRepository(fallback)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ec := appcontext.NewGinContext(ctx, "txn-123", nil)
	override := &gorm.DB{}
	ec.SetDatabase(override)

	if repo.dbForContext(ec) != override {
		t.Fatal("expected context database to win")
	}
	if repo.dbForContext(nil) != fallback {
		t.Fatal("expected fallback database when context is nil")
	}
}

// TestAssetRepositoryCreateForUserRejectsInvalidInput verifies invalid asset input is rejected before database use.
func TestAssetRepositoryCreateForUserRejectsInvalidInput(t *testing.T) {
	repo := NewAssetRepository(nil)

	if _, err := repo.CreateForUser(nil, "", model.Asset{}); !errors.Is(err, ErrNotNullViolation) {
		t.Fatalf("expected invalid data error, got %v", err)
	}
}
