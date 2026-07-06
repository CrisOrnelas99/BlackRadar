// Package repository verifies refresh session repository behavior.
package repository

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/model"
	baserepository "secureops/backend-go/api/repository"
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
