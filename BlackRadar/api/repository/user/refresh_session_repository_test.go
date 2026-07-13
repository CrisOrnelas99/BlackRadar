// Package repository verifies refresh session repository behavior.
package repository

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	appcontext "blackradar/api/context"
	"blackradar/api/model"
	baserepository "blackradar/api/repository"
)

// TestRefreshSessionRepositoryDatabasePrefersContextDB verifies the context database is preferred.
func TestRefreshSessionRepositoryDatabasePrefersContextDB(t *testing.T) {
	fallback := &gorm.DB{}
	repo := NewRefreshSessionRepository(fallback)

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

// TestRefreshSessionRepositorySaveRejectsInvalidInput verifies invalid refresh session input is rejected before database use.
func TestRefreshSessionRepositorySaveRejectsInvalidInput(t *testing.T) {
	repo := NewRefreshSessionRepository(nil)

	if err := repo.Save(nil, model.RefreshSession{}); err != baserepository.ErrInvalidData {
		t.Fatalf("expected invalid data error, got %v", err)
	}

	if err := repo.Save(nil, model.RefreshSession{
		TokenID:    "token-1",
		UserID:     "00000000-0000-4000-8000-000000000001",
		DeviceName: "desktop",
		ExpiresAt:  time.Time{},
	}); err != baserepository.ErrInvalidData {
		t.Fatalf("expected invalid data error for missing expiry, got %v", err)
	}
}

// TestActiveRefreshSessionQueryRequiresUnexpiredSession verifies expired sessions are not treated as active.
func TestActiveRefreshSessionQueryRequiresUnexpiredSession(t *testing.T) {
	database, err := gorm.Open(
		postgres.New(postgres.Config{DSN: "", PreferSimpleProtocol: true}),
		&gorm.Config{DryRun: true, DisableAutomaticPing: true},
	)
	if err != nil {
		t.Fatalf("failed to create dry-run database: %v", err)
	}

	query := activeRefreshSessionQuery(
		database,
		"token-1",
		"00000000-0000-4000-8000-000000000001",
		time.Unix(100, 0).UTC(),
	).First(&model.RefreshSession{})

	sql := query.Statement.SQL.String()
	if !strings.Contains(sql, "expires_at >") {
		t.Fatalf("expected active session query to require unexpired sessions, got SQL %q", sql)
	}
}
