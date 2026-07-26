// Package service verifies asset service behavior.
package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
	assetrepo "blackradar/api/repository/asset"
	vulnrepo "blackradar/api/repository/vulnerability"
	textgenerationservice "blackradar/api/service/text_generation"
)

// TestAssetService verifies the happy-path asset service flow.
func TestAssetService(t *testing.T) {
	repo := &fakeAssetRepository{asset: sampleAsset(), assets: []model.Asset{sampleAsset()}}
	svc := NewAssetService(repo, nil)
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
	if err := validateAsset(sampleAsset()); err != nil {
		t.Fatalf("expected valid asset, got %v", err)
	}
	if !errors.Is(translateAssetRepositoryError(assetrepo.ErrRecordNotFound), ErrAssetNotFound) {
		t.Fatal("expected not found translation")
	}
	if !errors.Is(translateAssetRepositoryError(assetrepo.ErrNotNullViolation), ErrInvalidAssetData) {
		t.Fatal("expected invalid request data translation")
	}

	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000007", "00000000-0000-4000-8000-000000000099")
	if id, err := authenticatedUserID(ctx); err != nil || id != "00000000-0000-4000-8000-000000000007" {
		t.Fatalf("expected user id UUID, got %s err=%v", id, err)
	}
}

// TestAssetServiceValidationAndTranslation verifies validation and error mapping.
func TestAssetServiceValidationAndTranslation(t *testing.T) {
	svc := NewAssetService(&fakeAssetRepository{findErr: assetrepo.ErrRecordNotFound}, nil)
	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000042", "00000000-0000-4000-8000-000000000099")

	if _, err := svc.GetAsset(ctx, "00000000-0000-4000-8000-000000000001"); !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("expected not found translation, got %v", err)
	}
	if _, err := svc.CreateAsset(ctx, model.Asset{}); !errors.Is(err, ErrInvalidAssetData) {
		t.Fatalf("expected invalid request data, got %v", err)
	}
}

func TestAssetServiceErrorsExposeCategories(t *testing.T) {
	var validationErr *ValidationError
	if !errors.As(ErrInvalidAssetData, &validationErr) {
		t.Fatal("expected invalid asset data to be an asset validation error")
	}
	var conflictErr *ConflictError
	if !errors.As(ErrDuplicateAsset, &conflictErr) {
		t.Fatal("expected duplicate asset to be an asset conflict error")
	}
	var forbiddenErr *ForbiddenError
	if !errors.As(ErrAssetPermissionDenied, &forbiddenErr) {
		t.Fatal("expected permission denied to be an asset permission error")
	}
	var notFoundErr *NotFoundError
	if !errors.As(ErrAssetNotFound, &notFoundErr) {
		t.Fatal("expected asset not found to be an asset not found error")
	}
	var dependencyErr *DependencyError
	if !errors.As(ErrAssetDependency, &dependencyErr) {
		t.Fatal("expected asset dependency failure to be an asset dependency error")
	}
	if !errors.As(ErrAssetExternalService, &dependencyErr) {
		t.Fatal("expected external service failure to be an asset dependency error")
	}
	var internalErr *InternalError
	if !errors.As(ErrAssetInternal, &internalErr) {
		t.Fatal("expected asset internal failure to be an asset internal error")
	}
}

func TestAssetServiceCreateAssetNormalizesDisplayFields(t *testing.T) {
	repo := &fakeAssetRepository{}
	svc := NewAssetService(repo, nil)
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

func TestAssetServiceRejectsDuplicateAssetSignaturePerUser(t *testing.T) {
	repo := &fakeAssetRepository{signatureExists: true}
	svc := NewAssetService(repo, nil)
	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000042", "00000000-0000-4000-8000-000000000099")

	_, err := svc.CreateAsset(ctx, model.Asset{
		Name:        "Asset A",
		Type:        "Cloud Service",
		Vendor:      stringPtr("Amazon"),
		Product:     stringPtr("Athena"),
		Owner:       "cloud engineer",
		Criticality: "Medium",
	})
	if !errors.Is(err, ErrDuplicateAsset) {
		t.Fatalf("expected duplicate asset signature to be rejected with conflict, got %v", err)
	}
}

func TestAssetServiceRejectsWrongUser(t *testing.T) {
	repo := &fakeAssetRepository{asset: sampleAsset(), expectedUserID: "00000000-0000-4000-8000-000000000099"}
	svc := NewAssetService(repo, nil)
	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000042", "00000000-0000-4000-8000-000000000100")

	if _, err := svc.GetAsset(ctx, "00000000-0000-4000-8000-000000000001"); !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("expected wrong user access to be hidden as not found, got %v", err)
	}
}

func TestAssetServiceCreateAssetFromAI(t *testing.T) {
	createdAsset := sampleAsset()
	createdAsset.ID = "00000000-0000-4000-8000-000000000088"
	repo := &fakeAssetRepository{asset: createdAsset}
	ai := &fakeTextGenerationService{
		response: textgenerationservice.TextGenerationResponse{
			Text: `{"name":"Ring Video Doorbell","type":"IoT Camera","operatingSystem":"Ring Firmware","vendor":"Amazon","product":"Ring Video Doorbell Firmware","version":"3.4.6","deviceModel":"Ring Video Doorbell","owner":"","criticality":"","confidence":0.91,"reviewNotes":"single asset extracted"}`,
		},
	}
	svc := NewAssetService(repo, ai)
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
		response: textgenerationservice.TextGenerationResponse{
			Text: `{"name":"WP-Ultimate-Map WordPress Plugin","type":"Web Application","operatingSystem":"WordPress","vendor":"","product":"WP-Ultimate-Map","version":"1.1","deviceModel":"","owner":"","criticality":"","confidence":0.86,"reviewNotes":"single asset extracted"}`,
		},
	}
	svc := NewAssetService(repo, ai)
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

type fakeAssetRepository struct {
	assets           []model.Asset
	asset            model.Asset
	saved            model.Asset
	findErr          error
	assigned         bool
	signatureExists  bool
	expectedUserID   string
	matchUpdate      assetrepo.AssetMatchUpdate
	updateMatchCalls int
	findByIDCalls    int
}

// FindAllByUser returns the configured fake asset list.
func (f *fakeAssetRepository) FindAllByUser(ec *appcontext.GinContext, userID string) ([]model.Asset, error) {
	if f.expectedUserID != "" && userID != f.expectedUserID {
		return nil, assetrepo.ErrRecordNotFound
	}
	return f.assets, f.findErr
}

// FindByIDForUser returns the configured fake asset.
func (f *fakeAssetRepository) FindByIDForUser(ec *appcontext.GinContext, id string, userID string) (model.Asset, error) {
	f.findByIDCalls++
	if f.expectedUserID != "" && userID != f.expectedUserID {
		return model.Asset{}, assetrepo.ErrRecordNotFound
	}
	if f.findErr != nil {
		return model.Asset{}, f.findErr
	}
	return f.asset, nil
}

// ExistsBySignatureForUser reports whether the fake duplicate exists.
func (f *fakeAssetRepository) ExistsBySignatureForUser(ec *appcontext.GinContext, asset model.Asset, userID string) (bool, error) {
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

// UpdateForUser returns the supplied fake asset.
func (f *fakeAssetRepository) UpdateForUser(ec *appcontext.GinContext, id string, userID string, asset model.Asset) (model.Asset, error) {
	return asset, nil
}

// UpdateMatchAnalysisForUser returns the configured fake asset after recording the match update.
func (f *fakeAssetRepository) UpdateMatchAnalysisForUser(ec *appcontext.GinContext, id string, userID string, analysis any) (model.Asset, error) {
	f.updateMatchCalls++
	if typed, ok := analysis.(assetrepo.AssetMatchUpdate); ok {
		f.matchUpdate = typed
	}
	return f.asset, nil
}

// DeleteForUser returns the configured fake asset.
func (f *fakeAssetRepository) DeleteForUser(ec *appcontext.GinContext, id string, userID string) (model.Asset, error) {
	return f.asset, nil
}

// AssignVulnerabilityForUser returns the configured fake asset.
func (f *fakeAssetRepository) AssignVulnerabilityForUser(ec *appcontext.GinContext, assetID string, userID string, vulnerabilityID string) (model.Asset, error) {
	f.assigned = true
	return f.asset, nil
}

// RemoveVulnerabilityForUser returns the configured fake asset.
func (f *fakeAssetRepository) RemoveVulnerabilityForUser(ec *appcontext.GinContext, assetID string, userID string, vulnerabilityID string) (model.Asset, error) {
	return f.asset, nil
}

var _ assetrepo.AssetRepositoryInterface = (*fakeAssetRepository)(nil)

type fakeVulnerabilityRepository struct {
	findErr error
	saved   model.Vulnerability
	updated model.Vulnerability
}

func (f *fakeVulnerabilityRepository) FindAllByUser(ec *appcontext.GinContext, userID string) ([]model.Vulnerability, error) {
	return nil, nil
}

func (f *fakeVulnerabilityRepository) FindByIDForUser(ec *appcontext.GinContext, id string, userID string) (model.Vulnerability, error) {
	return model.Vulnerability{}, nil
}

func (f *fakeVulnerabilityRepository) ExistsByCVEIDForUser(ec *appcontext.GinContext, cveID string, userID string) (bool, error) {
	return false, nil
}

func (f *fakeVulnerabilityRepository) ExistsByCVEIDExcludingIDForUser(ec *appcontext.GinContext, cveID string, id string, userID string) (bool, error) {
	return false, nil
}

func (f *fakeVulnerabilityRepository) FindByCVEIDForUser(ec *appcontext.GinContext, cveID string, userID string) (model.Vulnerability, error) {
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

func (f *fakeVulnerabilityRepository) UpdateForUser(ec *appcontext.GinContext, id string, userID string, vulnerability model.Vulnerability) (model.Vulnerability, error) {
	f.updated = vulnerability
	f.updated.ID = id
	return f.updated, nil
}

func (f *fakeVulnerabilityRepository) DeleteForUser(ec *appcontext.GinContext, id string, userID string) (model.Vulnerability, error) {
	return model.Vulnerability{}, nil
}

var _ vulnrepo.VulnerabilityRepositoryInterface = (*fakeVulnerabilityRepository)(nil)

type fakeTextGenerationService struct {
	response    textgenerationservice.TextGenerationResponse
	responses   []textgenerationservice.TextGenerationResponse
	err         error
	lastRequest textgenerationservice.TextGenerationRequest
	requests    []textgenerationservice.TextGenerationRequest
}

func (f *fakeTextGenerationService) GenerateText(ctx context.Context, request textgenerationservice.TextGenerationRequest) (textgenerationservice.TextGenerationResponse, error) {
	f.lastRequest = request
	f.requests = append(f.requests, request)
	if len(f.responses) > 0 {
		response := f.responses[0]
		f.responses = f.responses[1:]
		return response, f.err
	}
	return f.response, f.err
}

var _ textgenerationservice.TextGenerationService = (*fakeTextGenerationService)(nil)

// newServiceContext creates a request context with an authenticated user ID.
func newServiceContext(t *testing.T, userID string, organizationID string) *appcontext.GinContext {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ec := appcontext.NewGinContext(ctx, "txn-123", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := ec.SetPrincipal(appcontext.Principal{
		UserID:   userID,
		Username: "analyst",
		Role:     model.RoleUser,
	}); err != nil {
		t.Fatalf("failed to set test principal: %v", err)
	}
	appcontext.SetGinContext(ctx, ec)
	return ec
}

// sampleAsset returns a reusable asset fixture.
func sampleAsset() model.Asset {
	return model.Asset{Name: "Asset 1", Type: "Server", Owner: "IT", Criticality: "High"}
}

func stringPtr(value string) *string {
	return &value
}
