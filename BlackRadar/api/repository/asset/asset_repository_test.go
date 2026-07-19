// Package repository verifies asset repository behavior.
package repository

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

// TestAssetRepositoryErrors verifies asset repository errors are storage outcome sentinels.
func TestAssetRepositoryErrors(t *testing.T) {
	err := errors.Join(ErrPersistenceFailure, errors.New("database unavailable"))
	if !errors.Is(err, ErrPersistenceFailure) {
		t.Fatal("expected wrapped persistence failure to match sentinel")
	}
	if errors.Is(err, ErrInvalidData) {
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

// TestAssignRandomAssetAssessmentID verifies linked assessments use explicit random IDs before persistence.
func TestAssignRandomAssetAssessmentID(t *testing.T) {
	assessment := model.AssetAssessment{
		CPEReviewStatus: model.AssetCPEReviewStatusNeedsReview,
	}

	if assessment.ID != "" {
		t.Fatal("expected zero-value assessment id before initialization")
	}

	assignRandomAssetAssessmentID(&assessment)

	if assessment.ID == "" || len(assessment.ID) != 36 {
		t.Fatalf("expected UUID assessment id, got %q", assessment.ID)
	}
	if assessment.CPEReviewStatus != model.AssetCPEReviewStatusNeedsReview {
		t.Fatalf("expected review status to remain %q, got %q", model.AssetCPEReviewStatusNeedsReview, assessment.CPEReviewStatus)
	}
}

// TestAssetRepositorySaveRejectsInvalidInput verifies invalid asset input is rejected before database use.
func TestAssetRepositorySaveRejectsInvalidInput(t *testing.T) {
	repo := NewAssetRepository(nil)

	if _, err := repo.Save(nil, model.Asset{}); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("expected invalid data error, got %v", err)
	}
}
