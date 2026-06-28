// Package repository verifies organization repository behavior.
package repository

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/model"
	baserepository "secureops/backend-go/api/repository"
)

// TestOrganizationRepositoryDatabasePrefersContextDB verifies the context database is preferred.
func TestOrganizationRepositoryDatabasePrefersContextDB(t *testing.T) {
	fallback := &gorm.DB{}
	repo := NewOrganizationRepository(fallback)

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

// TestOrganizationRepositorySaveRejectsBlankName verifies invalid organization input is rejected before database use.
func TestOrganizationRepositorySaveRejectsBlankName(t *testing.T) {
	repo := NewOrganizationRepository(nil)

	if _, err := repo.Save(nil, model.Organization{Name: "   "}); err != baserepository.ErrInvalidData {
		t.Fatalf("expected invalid data error, got %v", err)
	}
}
