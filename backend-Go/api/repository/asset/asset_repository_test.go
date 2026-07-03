// Package repository verifies asset repository behavior.
package repository

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/model"
)

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

// TestAssignRandomAssetAssessmentID verifies linked assessments use explicit random IDs before persistence.
func TestAssignRandomAssetAssessmentID(t *testing.T) {
	assessment := model.AssetAssessment{
		CPEReviewStatus: model.AssetCPEReviewStatusNeedsReview,
	}

	if assessment.ID != 0 {
		t.Fatal("expected zero-value assessment id before initialization")
	}

	assignRandomAssetAssessmentID(&assessment)

	if assessment.ID <= 0 {
		t.Fatalf("expected positive random assessment id, got %d", assessment.ID)
	}
	if assessment.CPEReviewStatus != model.AssetCPEReviewStatusNeedsReview {
		t.Fatalf("expected review status to remain %q, got %q", model.AssetCPEReviewStatusNeedsReview, assessment.CPEReviewStatus)
	}
}
