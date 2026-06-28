// Package service verifies asset service behavior.
package service

import (
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/dto"
	"secureops/backend-go/api/model"
	baserepository "secureops/backend-go/api/repository"
	baseservice "secureops/backend-go/api/service"
)

// TestAssetService verifies the happy-path asset service flow.
func TestAssetService(t *testing.T) {
	repo := &fakeAssetRepository{asset: sampleAsset(), assets: []model.Asset{sampleAsset()}}
	svc := NewAssetService(repo, &fakeVulnerabilityRepository{}, &fakeNVDLookupService{})
	ctx := newServiceContext(t, 42)

	if _, err := svc.GetAllAssets(ctx); err != nil {
		t.Fatalf("expected GetAllAssets to succeed, got %v", err)
	}
	if _, err := svc.CreateAsset(ctx, sampleAsset()); err != nil {
		t.Fatalf("expected CreateAsset to succeed, got %v", err)
	}
	if _, err := svc.UpdateAsset(ctx, 1, sampleAsset()); err != nil {
		t.Fatalf("expected UpdateAsset to succeed, got %v", err)
	}
}

// TestAssetServiceHelpers verifies asset service helper behavior.
func TestAssetServiceHelpers(t *testing.T) {
	if err := baseservice.ValidateAsset(sampleAsset()); err != nil {
		t.Fatalf("expected valid asset, got %v", err)
	}
	if !errors.Is(baseservice.TranslateRepositoryError(baserepository.ErrAssetNotFound), baseservice.ErrNotFound) {
		t.Fatal("expected not found translation")
	}
	if !errors.Is(baseservice.TranslateRepositoryError(baserepository.ErrDuplicateAssignment), baseservice.ErrConflict) {
		t.Fatal("expected conflict translation")
	}
	if !errors.Is(baseservice.TranslateRepositoryError(baserepository.ErrInvalidData), baseservice.ErrInvalidRequestData) {
		t.Fatal("expected invalid request data translation")
	}

	ctx := newServiceContext(t, 7)
	if id, err := baseservice.AuthenticatedUserID(ctx); err != nil || id != 7 {
		t.Fatalf("expected user id 7, got %d err=%v", id, err)
	}
}

// TestAssetServiceValidationAndTranslation verifies validation and error mapping.
func TestAssetServiceValidationAndTranslation(t *testing.T) {
	svc := NewAssetService(&fakeAssetRepository{findErr: baserepository.ErrAssetNotFound}, &fakeVulnerabilityRepository{}, &fakeNVDLookupService{})
	ctx := newServiceContext(t, 42)

	if _, err := svc.GetAsset(ctx, 1); !errors.Is(err, baseservice.ErrNotFound) {
		t.Fatalf("expected not found translation, got %v", err)
	}
	if _, err := svc.CreateAsset(ctx, model.Asset{}); !errors.Is(err, baseservice.ErrInvalidRequestData) {
		t.Fatalf("expected invalid request data, got %v", err)
	}
}

// TestAssetServiceAssignVulnerabilityByCVE verifies the NVD-backed assignment flow stores local data.
func TestAssetServiceAssignVulnerabilityByCVE(t *testing.T) {
	assetRepo := &fakeAssetRepository{asset: sampleAsset()}
	vulnRepo := &fakeVulnerabilityRepository{findErr: baserepository.ErrVulnerabilityNotFound}
	nvdSvc := &fakeNVDLookupService{response: dto.CVELookupResponse{
		CVEID:       "CVE-2024-3094",
		Title:       "XZ Utils Backdoor",
		Description: "Example NVD response",
		Severity:    "Critical",
	}}
	svc := NewAssetService(assetRepo, vulnRepo, nvdSvc)
	ctx := newServiceContext(t, 42)

	assigned, err := svc.AssignVulnerabilityByCVE(ctx, 1, "cve-2024-3094")
	if err != nil {
		t.Fatalf("expected assign by cve to succeed, got %v", err)
	}
	if assigned.ID != assetRepo.asset.ID {
		t.Fatalf("expected assigned asset to be returned, got %d", assigned.ID)
	}
	if !nvdSvc.called {
		t.Fatal("expected NVD lookup to be called")
	}
	if vulnRepo.saved.CVEID != "CVE-2024-3094" {
		t.Fatalf("expected local vulnerability to be saved, got %q", vulnRepo.saved.CVEID)
	}
}

type fakeAssetRepository struct {
	assets   []model.Asset
	asset    model.Asset
	findErr  error
	assigned bool
}

// FindAllByUser returns the configured fake asset list.
func (f *fakeAssetRepository) FindAllByUser(ec *appcontext.GinContext, userID int64) ([]model.Asset, error) {
	return f.assets, f.findErr
}

// FindByIDForUser returns the configured fake asset.
func (f *fakeAssetRepository) FindByIDForUser(ec *appcontext.GinContext, id int64, userID int64) (model.Asset, error) {
	if f.findErr != nil {
		return model.Asset{}, f.findErr
	}
	return f.asset, nil
}

// Save returns the supplied fake asset.
func (f *fakeAssetRepository) Save(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error) {
	return asset, nil
}

// UpdateForUser returns the supplied fake asset.
func (f *fakeAssetRepository) UpdateForUser(ec *appcontext.GinContext, id int64, userID int64, asset model.Asset) (model.Asset, error) {
	return asset, nil
}

// DeleteForUser returns the configured fake asset.
func (f *fakeAssetRepository) DeleteForUser(ec *appcontext.GinContext, id int64, userID int64) (model.Asset, error) {
	return f.asset, nil
}

// AssignVulnerabilityForUser returns the configured fake asset.
func (f *fakeAssetRepository) AssignVulnerabilityForUser(ec *appcontext.GinContext, assetID int64, userID int64, vulnerabilityID int64) (model.Asset, error) {
	f.assigned = true
	return f.asset, nil
}

// RemoveVulnerabilityForUser returns the configured fake asset.
func (f *fakeAssetRepository) RemoveVulnerabilityForUser(ec *appcontext.GinContext, assetID int64, userID int64, vulnerabilityID int64) (model.Asset, error) {
	return f.asset, nil
}

var _ baserepository.AssetRepository = (*fakeAssetRepository)(nil)

type fakeVulnerabilityRepository struct {
	findErr error
	saved   model.Vulnerability
	updated model.Vulnerability
}

func (f *fakeVulnerabilityRepository) FindAllByUser(ec *appcontext.GinContext, userID int64) ([]model.Vulnerability, error) {
	return nil, nil
}

func (f *fakeVulnerabilityRepository) FindByIDForUser(ec *appcontext.GinContext, id int64, userID int64) (model.Vulnerability, error) {
	return model.Vulnerability{}, nil
}

func (f *fakeVulnerabilityRepository) ExistsByCVEIDForUser(ec *appcontext.GinContext, cveID string, userID int64) (bool, error) {
	return false, nil
}

func (f *fakeVulnerabilityRepository) ExistsByCVEIDExcludingIDForUser(ec *appcontext.GinContext, cveID string, id int64, userID int64) (bool, error) {
	return false, nil
}

func (f *fakeVulnerabilityRepository) FindByCVEIDForUser(ec *appcontext.GinContext, cveID string, userID int64) (model.Vulnerability, error) {
	if f.findErr != nil {
		return model.Vulnerability{}, f.findErr
	}
	return f.saved, nil
}

func (f *fakeVulnerabilityRepository) Save(ec *appcontext.GinContext, vulnerability model.Vulnerability) (model.Vulnerability, error) {
	f.saved = vulnerability
	f.saved.ID = 99
	return f.saved, nil
}

func (f *fakeVulnerabilityRepository) UpdateForUser(ec *appcontext.GinContext, id int64, userID int64, vulnerability model.Vulnerability) (model.Vulnerability, error) {
	f.updated = vulnerability
	f.updated.ID = id
	return f.updated, nil
}

func (f *fakeVulnerabilityRepository) DeleteForUser(ec *appcontext.GinContext, id int64, userID int64) (model.Vulnerability, error) {
	return model.Vulnerability{}, nil
}

var _ baserepository.VulnerabilityRepository = (*fakeVulnerabilityRepository)(nil)

type fakeNVDLookupService struct {
	response dto.CVELookupResponse
	err      error
	called   bool
}

func (f *fakeNVDLookupService) LookupCVE(ec *appcontext.GinContext, cveID string) (dto.CVELookupResponse, error) {
	f.called = true
	return f.response, f.err
}

var _ baseservice.NVDLookupService = (*fakeNVDLookupService)(nil)

// newServiceContext creates a request context with an authenticated user ID.
func newServiceContext(t *testing.T, userID int64) *appcontext.GinContext {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ec := appcontext.NewGinContext(ctx, "txn-123", log.New(io.Discard, "", 0))
	ec.SetUserID(userID)
	appcontext.SetGinContext(ctx, ec)
	return ec
}

// sampleAsset returns a reusable asset fixture.
func sampleAsset() model.Asset {
	return model.Asset{Name: "Asset 1", Type: "Server", IPAddress: "10.0.0.10", Owner: "IT", Criticality: "High"}
}
