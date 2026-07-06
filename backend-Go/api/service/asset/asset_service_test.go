// Package service verifies asset service behavior.
package service

import (
	"errors"
	"io"
	"log/slog"
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
	svc := NewAssetService(repo, &fakeVulnerabilityRepository{}, &fakeNVDLookupService{}, nil)
	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000042", "00000000-0000-4000-8000-000000000099")

	if _, err := svc.GetAllAssets(ctx); err != nil {
		t.Fatalf("expected GetAllAssets to succeed, got %v", err)
	}
	if _, err := svc.CreateAsset(ctx, sampleAsset()); err != nil {
		t.Fatalf("expected CreateAsset to succeed, got %v", err)
	}
	if repo.saved.Name != "Asset 1" || repo.saved.Owner != "IT" {
		t.Fatalf("expected manual asset fields to stay title-cased, got name=%q owner=%q", repo.saved.Name, repo.saved.Owner)
	}
	if _, err := svc.UpdateAsset(ctx, "00000000-0000-4000-8000-000000000001", sampleAsset()); err != nil {
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

	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000007", "00000000-0000-4000-8000-000000000099")
	if id, err := baseservice.AuthenticatedUserID(ctx); err != nil || id != "00000000-0000-4000-8000-000000000007" {
		t.Fatalf("expected user id UUID, got %s err=%v", id, err)
	}
	if orgID, err := baseservice.AuthenticatedOrganizationID(ctx); err != nil || orgID != "00000000-0000-4000-8000-000000000099" {
		t.Fatalf("expected organization id 99, got %s err=%v", orgID, err)
	}
}

// TestAssetServiceValidationAndTranslation verifies validation and error mapping.
func TestAssetServiceValidationAndTranslation(t *testing.T) {
	svc := NewAssetService(&fakeAssetRepository{findErr: baserepository.ErrAssetNotFound}, &fakeVulnerabilityRepository{}, &fakeNVDLookupService{}, nil)
	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000042", "00000000-0000-4000-8000-000000000099")

	if _, err := svc.GetAsset(ctx, "00000000-0000-4000-8000-000000000001"); !errors.Is(err, baseservice.ErrNotFound) {
		t.Fatalf("expected not found translation, got %v", err)
	}
	if _, err := svc.CreateAsset(ctx, model.Asset{}); !errors.Is(err, baseservice.ErrInvalidRequestData) {
		t.Fatalf("expected invalid request data, got %v", err)
	}
}

func TestAssetServiceCreateAssetNormalizesDisplayFields(t *testing.T) {
	repo := &fakeAssetRepository{}
	svc := NewAssetService(repo, &fakeVulnerabilityRepository{}, &fakeNVDLookupService{}, nil)
	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000042", "00000000-0000-4000-8000-000000000099")

	created, err := svc.CreateAsset(ctx, model.Asset{
		Name:        "aws athena",
		Type:        "cloud service",
		Vendor:      stringPtr("amazon"),
		Product:     stringPtr("athena"),
		Owner:       "cloud engineer",
		Criticality: "medium",
	})
	if err != nil {
		t.Fatalf("expected create asset to succeed, got %v", err)
	}
	if created.Name != "AWS Athena" {
		t.Fatalf("expected normalized name, got %q", created.Name)
	}
	if repo.saved.Owner != "Cloud Engineer" {
		t.Fatalf("expected normalized owner, got %q", repo.saved.Owner)
	}
	if got := optionalString(repo.saved.Vendor); got != "Amazon" {
		t.Fatalf("expected normalized vendor, got %q", got)
	}
	if got := optionalString(repo.saved.Product); got != "Athena" {
		t.Fatalf("expected normalized product, got %q", got)
	}
}

func TestAssetServiceRejectsDuplicateAssetSignaturePerOrganization(t *testing.T) {
	repo := &fakeAssetRepository{signatureExists: true}
	svc := NewAssetService(repo, &fakeVulnerabilityRepository{}, &fakeNVDLookupService{}, nil)
	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000042", "00000000-0000-4000-8000-000000000099")

	_, err := svc.CreateAsset(ctx, model.Asset{
		Name:        "Asset A",
		Type:        "Cloud Service",
		Vendor:      stringPtr("Amazon"),
		Product:     stringPtr("Athena"),
		Owner:       "cloud engineer",
		Criticality: "Medium",
	})
	if !errors.Is(err, baseservice.ErrConflict) {
		t.Fatalf("expected duplicate asset signature to be rejected with conflict, got %v", err)
	}
}

func TestAssetServiceRejectsWrongOrganization(t *testing.T) {
	repo := &fakeAssetRepository{asset: sampleAsset(), expectedOrganizationID: "00000000-0000-4000-8000-000000000099"}
	svc := NewAssetService(repo, &fakeVulnerabilityRepository{}, &fakeNVDLookupService{}, nil)
	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000042", "00000000-0000-4000-8000-000000000100")

	if _, err := svc.GetAsset(ctx, "00000000-0000-4000-8000-000000000001"); !errors.Is(err, baseservice.ErrNotFound) {
		t.Fatalf("expected wrong organization access to be hidden as not found, got %v", err)
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
	svc := NewAssetService(assetRepo, vulnRepo, nvdSvc, nil)
	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000042", "00000000-0000-4000-8000-000000000099")
	ctx.SetUserRole(model.RoleAdmin)

	assigned, err := svc.AssignVulnerabilityByCVE(ctx, "00000000-0000-4000-8000-000000000001", "cve-2024-3094")
	if err != nil {
		t.Fatalf("expected assign by cve to succeed, got %v", err)
	}
	if assigned.ID != assetRepo.asset.ID {
		t.Fatalf("expected assigned asset to be returned, got %s", assigned.ID)
	}
	if !nvdSvc.called {
		t.Fatal("expected NVD lookup to be called")
	}
	if vulnRepo.saved.CVEID != "CVE-2024-3094" {
		t.Fatalf("expected local vulnerability to be saved, got %q", vulnRepo.saved.CVEID)
	}
}

func TestAssetServiceCreateAssetFromAI(t *testing.T) {
	createdAsset := sampleAsset()
	createdAsset.ID = "00000000-0000-4000-8000-000000000088"
	repo := &fakeAssetRepository{asset: createdAsset}
	ai := &fakeTextGenerationService{
		response: dto.TextGenerationResponse{
			Text: `{"name":"Ring Video Doorbell","type":"IoT Camera","operatingSystem":"Ring Firmware","vendor":"Amazon","product":"Ring Video Doorbell Firmware","version":"3.4.6","deviceModel":"Ring Video Doorbell","owner":"","criticality":"","confidence":0.91,"reviewNotes":"single asset extracted"}`,
		},
	}
	svc := NewAssetService(repo, &fakeVulnerabilityRepository{}, &fakeNVDLookupService{}, ai)
	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000042", "00000000-0000-4000-8000-000000000099")
	ctx.SetUserRole(model.RoleAdmin)

	asset, err := svc.CreateAssetFromAI(ctx, "I have an Amazon Ring Video Doorbell running firmware 3.4.6.")
	if err != nil {
		t.Fatalf("expected ai asset creation to succeed, got %v", err)
	}
	if asset.ID != "00000000-0000-4000-8000-000000000088" {
		t.Fatalf("expected created asset id UUID, got %s", asset.ID)
	}
	if repo.saved.Name != "Ring Video Doorbell" {
		t.Fatalf("expected ai-created asset name, got %q", repo.saved.Name)
	}
	if repo.saved.Owner != "Unassigned" {
		t.Fatalf("expected safe owner default, got %q", repo.saved.Owner)
	}
	if repo.saved.Criticality != "Medium" {
		t.Fatalf("expected safe criticality default, got %q", repo.saved.Criticality)
	}
}

func TestAssetServiceCreateAssetFromAIAllowsNoNetworkAddressField(t *testing.T) {
	createdAsset := sampleAsset()
	createdAsset.ID = "00000000-0000-4000-8000-000000000089"
	repo := &fakeAssetRepository{asset: createdAsset}
	ai := &fakeTextGenerationService{
		response: dto.TextGenerationResponse{
			Text: `{"name":"WP-Ultimate-Map WordPress Plugin","type":"Web Application","operatingSystem":"WordPress","vendor":"","product":"WP-Ultimate-Map","version":"1.1","deviceModel":"","owner":"","criticality":"","confidence":0.86,"reviewNotes":"single asset extracted"}`,
		},
	}
	svc := NewAssetService(repo, &fakeVulnerabilityRepository{}, &fakeNVDLookupService{}, ai)
	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000042", "00000000-0000-4000-8000-000000000099")
	ctx.SetUserRole(model.RoleAdmin)

	asset, err := svc.CreateAssetFromAI(ctx, "We have WP-Ultimate-Map plugin Software for WordPress. The version number is 1.1")
	if err != nil {
		t.Fatalf("expected ai asset creation to succeed, got %v", err)
	}
	if asset.ID != "00000000-0000-4000-8000-000000000089" {
		t.Fatalf("expected created asset id UUID, got %s", asset.ID)
	}
	if repo.saved.Owner != "Unassigned" {
		t.Fatalf("expected safe owner default, got %q", repo.saved.Owner)
	}
	if repo.saved.Criticality != "Medium" {
		t.Fatalf("expected safe criticality default, got %q", repo.saved.Criticality)
	}
}

func TestAssetServiceRejectsVulnerabilityActionsForNonAdmin(t *testing.T) {
	svc := NewAssetService(&fakeAssetRepository{asset: sampleAsset()}, &fakeVulnerabilityRepository{}, &fakeNVDLookupService{}, nil)
	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000042", "00000000-0000-4000-8000-000000000099")
	ctx.SetUserRole(model.RoleUser)

	if _, err := svc.AssignVulnerability(ctx, "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"); !errors.Is(err, baseservice.ErrForbidden) {
		t.Fatalf("expected assign vulnerability to be forbidden, got %v", err)
	}
	if _, err := svc.AssignVulnerabilityByCVE(ctx, "00000000-0000-4000-8000-000000000001", "CVE-2024-3094"); !errors.Is(err, baseservice.ErrForbidden) {
		t.Fatalf("expected assign by cve to be forbidden, got %v", err)
	}
	if _, err := svc.RemoveVulnerability(ctx, "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"); !errors.Is(err, baseservice.ErrForbidden) {
		t.Fatalf("expected remove vulnerability to be forbidden, got %v", err)
	}
}

type fakeAssetRepository struct {
	assets                 []model.Asset
	asset                  model.Asset
	saved                  model.Asset
	findErr                error
	assigned               bool
	signatureExists        bool
	expectedOrganizationID string
	matchUpdate            baserepository.AssetMatchUpdate
	updateMatchCalls       int
}

// FindAllByUser returns the configured fake asset list.
func (f *fakeAssetRepository) FindAllByOrganization(ec *appcontext.GinContext, organizationID string) ([]model.Asset, error) {
	if f.expectedOrganizationID != "" && organizationID != f.expectedOrganizationID {
		return nil, baserepository.ErrAssetNotFound
	}
	return f.assets, f.findErr
}

// FindByIDForOrganization returns the configured fake asset.
func (f *fakeAssetRepository) FindByIDForOrganization(ec *appcontext.GinContext, id string, organizationID string) (model.Asset, error) {
	if f.expectedOrganizationID != "" && organizationID != f.expectedOrganizationID {
		return model.Asset{}, baserepository.ErrAssetNotFound
	}
	if f.findErr != nil {
		return model.Asset{}, f.findErr
	}
	return f.asset, nil
}

// ExistsBySignatureForOrganization reports whether the fake duplicate exists.
func (f *fakeAssetRepository) ExistsBySignatureForOrganization(ec *appcontext.GinContext, asset model.Asset, organizationID string) (bool, error) {
	return f.signatureExists, nil
}

// Save returns the supplied fake asset.
func (f *fakeAssetRepository) Save(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error) {
	if f.asset.ID != "" {
		asset.ID = f.asset.ID
	}
	f.saved = asset
	return asset, nil
}

// UpdateForOrganization returns the supplied fake asset.
func (f *fakeAssetRepository) UpdateForOrganization(ec *appcontext.GinContext, id string, organizationID string, asset model.Asset) (model.Asset, error) {
	return asset, nil
}

// UpdateMatchAnalysisForOrganization returns the configured fake asset after recording the match update.
func (f *fakeAssetRepository) UpdateMatchAnalysisForOrganization(ec *appcontext.GinContext, id string, organizationID string, analysis baserepository.AssetMatchUpdate) (model.Asset, error) {
	f.updateMatchCalls++
	f.matchUpdate = analysis
	return f.asset, nil
}

// DeleteForOrganization returns the configured fake asset.
func (f *fakeAssetRepository) DeleteForOrganization(ec *appcontext.GinContext, id string, organizationID string) (model.Asset, error) {
	return f.asset, nil
}

// AssignVulnerabilityForOrganization returns the configured fake asset.
func (f *fakeAssetRepository) AssignVulnerabilityForOrganization(ec *appcontext.GinContext, assetID string, organizationID string, vulnerabilityID string) (model.Asset, error) {
	f.assigned = true
	return f.asset, nil
}

// RemoveVulnerabilityForOrganization returns the configured fake asset.
func (f *fakeAssetRepository) RemoveVulnerabilityForOrganization(ec *appcontext.GinContext, assetID string, organizationID string, vulnerabilityID string) (model.Asset, error) {
	return f.asset, nil
}

var _ baserepository.AssetRepository = (*fakeAssetRepository)(nil)

type fakeVulnerabilityRepository struct {
	findErr error
	saved   model.Vulnerability
	updated model.Vulnerability
}

func (f *fakeVulnerabilityRepository) FindAllByOrganization(ec *appcontext.GinContext, organizationID string) ([]model.Vulnerability, error) {
	return nil, nil
}

func (f *fakeVulnerabilityRepository) FindByIDForOrganization(ec *appcontext.GinContext, id string, organizationID string) (model.Vulnerability, error) {
	return model.Vulnerability{}, nil
}

func (f *fakeVulnerabilityRepository) ExistsByCVEIDForOrganization(ec *appcontext.GinContext, cveID string, organizationID string) (bool, error) {
	return false, nil
}

func (f *fakeVulnerabilityRepository) ExistsByCVEIDExcludingIDForOrganization(ec *appcontext.GinContext, cveID string, id string, organizationID string) (bool, error) {
	return false, nil
}

func (f *fakeVulnerabilityRepository) FindByCVEIDForOrganization(ec *appcontext.GinContext, cveID string, organizationID string) (model.Vulnerability, error) {
	if f.findErr != nil {
		return model.Vulnerability{}, f.findErr
	}
	return f.saved, nil
}

func (f *fakeVulnerabilityRepository) Save(ec *appcontext.GinContext, vulnerability model.Vulnerability) (model.Vulnerability, error) {
	f.saved = vulnerability
	f.saved.ID = "00000000-0000-4000-8000-000000000099"
	return f.saved, nil
}

func (f *fakeVulnerabilityRepository) UpdateForOrganization(ec *appcontext.GinContext, id string, organizationID string, vulnerability model.Vulnerability) (model.Vulnerability, error) {
	f.updated = vulnerability
	f.updated.ID = id
	return f.updated, nil
}

func (f *fakeVulnerabilityRepository) DeleteForOrganization(ec *appcontext.GinContext, id string, organizationID string) (model.Vulnerability, error) {
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
func newServiceContext(t *testing.T, userID string, organizationID string) *appcontext.GinContext {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ec := appcontext.NewGinContext(ctx, "txn-123", slog.New(slog.NewTextHandler(io.Discard, nil)))
	ec.SetUserID(userID)
	ec.SetOrganizationID(organizationID)
	appcontext.SetGinContext(ctx, ec)
	return ec
}

// sampleAsset returns a reusable asset fixture.
func sampleAsset() model.Asset {
	return model.Asset{OrganizationID: "00000000-0000-4000-8000-000000000099", Name: "Asset 1", Type: "Server", Owner: "IT", Criticality: "High"}
}

func stringPtr(value string) *string {
	return &value
}
