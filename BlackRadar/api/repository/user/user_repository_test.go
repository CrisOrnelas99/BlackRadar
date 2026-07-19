// Package repository verifies user repository behavior.
package repository

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	appcontext "blackradar/api/platform/requestcontext"
)

// TestUserRepositoryDatabasePrefersContextDB verifies the context database is preferred.
func TestUserRepositoryDatabasePrefersContextDB(t *testing.T) {
	fallback := &gorm.DB{}
	repo := NewUserRepository(fallback)

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
