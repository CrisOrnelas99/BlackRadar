// Package repository verifies asset match repository behavior.
package repository

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	appcontext "blackradar/api/platform/requestcontext"
)

// TestAssetMatchRepositoryErrors verifies asset match repository errors are storage outcome sentinels.
func TestAssetMatchRepositoryErrors(t *testing.T) {
	err := errors.Join(ErrPersistenceFailure, errors.New("database unavailable"))
	if !errors.Is(err, ErrPersistenceFailure) {
		t.Fatal("expected wrapped persistence failure to match sentinel")
	}
	if errors.Is(err, ErrNotNullViolation) {
		t.Fatal("expected persistence failure to stay distinct from invalid data")
	}
}

// TestAssetMatchRepositoryDatabasePrefersContextDB verifies the context database is preferred.
func TestAssetMatchRepositoryDatabasePrefersContextDB(t *testing.T) {
	fallback := &gorm.DB{}
	repo := NewAssetMatchRepository(fallback)

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
