// Package service verifies asset service behavior.
package service

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
	assetrepo "blackradar/api/repository/asset"
	vulnrepo "blackradar/api/repository/vulnerability"
)

// TestAssetService verifies the happy-path asset service flow.
func TestAssetService(t *testing.T) {
	asset := sampleAsset()
	asset.Vulnerabilities = []model.Vulnerability{{Model: model.Model{ID: "vulnerability-1"}, Title: "Example vulnerability"}}
	repo := &fakeAssetRepository{asset: asset, assets: []model.Asset{asset}}
	svc := NewAssetService(repo)
	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000042")

	if _, err := svc.GetAllAssets(ctx); err != nil {
		t.Fatalf("expected GetAllAssets to succeed, got %v", err)
	}
	vulnerabilities, err := svc.GetAssetVulnerabilities(ctx, "00000000-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatalf("expected GetAssetVulnerabilities to succeed, got %v", err)
	}
	if len(vulnerabilities) != 1 || vulnerabilities[0].ID != "vulnerability-1" {
		t.Fatalf("expected attached vulnerability, got %+v", vulnerabilities)
	}
	if _, err := svc.CreateAsset(ctx, sampleAsset()); err != nil {
		t.Fatalf("expected CreateAsset to succeed, got %v", err)
	}
	if repo.saved.Name != "Asset 1" || repo.saved.Owner != "IT" {
		t.Fatalf("expected manual asset fields to stay title-cased, got name=%q owner=%q", repo.saved.Name, repo.saved.Owner)
	}
	if repo.saved.UserID != "00000000-0000-4000-8000-000000000042" {
		t.Fatalf("expected asset to be created for authenticated user, got %q", repo.saved.UserID)
	}
	if repo.saved.RiskLevel == nil || *repo.saved.RiskLevel != "Low" {
		t.Fatalf("expected new asset without vulnerabilities to have Low risk level, got %#v", repo.saved.RiskLevel)
	}
	if _, err := svc.UpdateAsset(ctx, "00000000-0000-4000-8000-000000000001", sampleAsset()); err != nil {
		t.Fatalf("expected UpdateAsset to succeed, got %v", err)
	}
}

// TestAssetServiceSupport verifies asset service support behavior.
func TestAssetServiceSupport(t *testing.T) {
	if err := validateAsset(sampleAsset()); err != nil {
		t.Fatalf("expected valid asset, got %v", err)
	}
	if !errors.Is(translateAssetRepositoryError(assetrepo.ErrRecordNotFound), ErrAssetNotFound) {
		t.Fatal("expected not found translation")
	}
	if !errors.Is(translateAssetRepositoryError(assetrepo.ErrNotNullViolation), ErrInvalidAssetData) {
		t.Fatal("expected invalid request data translation")
	}

	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000007")
	if id, err := authenticatedUserID(ctx); err != nil || id != "00000000-0000-4000-8000-000000000007" {
		t.Fatalf("expected user id UUID, got %s err=%v", id, err)
	}
}

// TestAssetServiceValidationAndTranslation verifies validation and error mapping.
func TestAssetServiceValidationAndTranslation(t *testing.T) {
	svc := NewAssetService(&fakeAssetRepository{findErr: assetrepo.ErrRecordNotFound})
	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000042")

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
	var internalErr *InternalError
	if !errors.As(ErrAssetInternal, &internalErr) {
		t.Fatal("expected asset internal failure to be an asset internal error")
	}
}

func TestAssetServiceCreateAssetNormalizesDisplayFields(t *testing.T) {
	repo := &fakeAssetRepository{}
	svc := NewAssetService(repo)
	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000042")
	description := "  primary production asset  "

	created, err := svc.CreateAsset(ctx, model.Asset{
		Name:        "aws athena",
		Type:        "cloud service",
		Description: &description,
		Vendor:      stringPtr("amazon"),
		Product:     stringPtr("athena"),
		Version:     stringPtr(" 2.0.1 "),
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
	if got := optionalString(repo.saved.Version); got != "2.0.1" {
		t.Fatalf("expected normalized version, got %q", got)
	}
	if got := optionalString(repo.saved.Description); got != "primary production asset" {
		t.Fatalf("expected normalized description, got %q", got)
	}
}

func TestAssetServiceRejectsOversizedDescription(t *testing.T) {
	description := strings.Repeat("a", maxAssetDescriptionLength+1)
	if err := validateAsset(model.Asset{Description: &description, Name: "Asset", Type: "Server", Vendor: stringPtr("Vendor"), Product: stringPtr("Product"), Version: stringPtr("1.0"), Criticality: "Medium"}); !errors.Is(err, ErrInvalidAssetData) {
		t.Fatalf("expected oversized description to be rejected, got %v", err)
	}
}

func TestAssetServiceRequiresCPEIdentityFields(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*model.Asset)
	}{
		{name: "vendor", modify: func(asset *model.Asset) { asset.Vendor = nil }},
		{name: "product", modify: func(asset *model.Asset) { asset.Product = nil }},
		{name: "version", modify: func(asset *model.Asset) { asset.Version = nil }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			asset := sampleAsset()
			test.modify(&asset)
			if err := validateAsset(asset); !errors.Is(err, ErrInvalidAssetData) {
				t.Fatalf("expected missing %s to be rejected, got %v", test.name, err)
			}
		})
	}
}

func TestAssetServiceDefaultsMissingOwner(t *testing.T) {
	repo := &fakeAssetRepository{}
	svc := NewAssetService(repo)
	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000042")
	asset := sampleAsset()
	asset.Owner = ""

	if _, err := svc.CreateAsset(ctx, asset); err != nil {
		t.Fatalf("expected an asset without an owner to use the default, got %v", err)
	}
	if repo.saved.Owner != defaultAssetOwner {
		t.Fatalf("expected default owner %q, got %q", defaultAssetOwner, repo.saved.Owner)
	}
}

func TestAssetServiceUpdateAssetIncludesDescription(t *testing.T) {
	repo := &fakeAssetRepository{}
	svc := NewAssetService(repo)
	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000042")
	description := "  Updated asset description  "

	_, err := svc.UpdateAsset(ctx, "00000000-0000-4000-8000-000000000001", model.Asset{
		Name:        "Asset 1",
		Type:        "Server",
		Description: &description,
		Vendor:      stringPtr("Vendor"),
		Product:     stringPtr("Product"),
		Version:     stringPtr("1.0"),
		Owner:       "IT",
		Criticality: "High",
	})
	if err != nil {
		t.Fatalf("expected update asset to succeed, got %v", err)
	}
	if got := optionalString(repo.saved.Description); got != "Updated asset description" {
		t.Fatalf("expected normalized description in update, got %q", got)
	}
}

func TestAssetServiceRejectsDuplicateAssetSignaturePerUser(t *testing.T) {
	repo := &fakeAssetRepository{signatureExists: true}
	svc := NewAssetService(repo)
	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000042")

	_, err := svc.CreateAsset(ctx, model.Asset{
		Name:        "Asset A",
		Type:        "Cloud Service",
		Vendor:      stringPtr("Amazon"),
		Product:     stringPtr("Athena"),
		Version:     stringPtr("1.0"),
		Owner:       "cloud engineer",
		Criticality: "Medium",
	})
	if !errors.Is(err, ErrDuplicateAsset) {
		t.Fatalf("expected duplicate asset signature to be rejected with conflict, got %v", err)
	}
}

func TestAssetServiceRejectsWrongUser(t *testing.T) {
	repo := &fakeAssetRepository{asset: sampleAsset(), expectedUserID: "00000000-0000-4000-8000-000000000099"}
	svc := NewAssetService(repo)
	ctx := newServiceContext(t, "00000000-0000-4000-8000-000000000042")

	if _, err := svc.GetAsset(ctx, "00000000-0000-4000-8000-000000000001"); !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("expected wrong user access to be hidden as not found, got %v", err)
	}
	if _, err := svc.GetAssetVulnerabilities(ctx, "00000000-0000-4000-8000-000000000001"); !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("expected attached vulnerability access for wrong user to be hidden as not found, got %v", err)
	}
}

type fakeAssetRepository struct {
	assets          []model.Asset
	asset           model.Asset
	saved           model.Asset
	findErr         error
	signatureExists bool
	expectedUserID  string
	findByIDCalls   int
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

func (f *fakeAssetRepository) FindVulnerabilitiesForAsset(ec *appcontext.GinContext, assetID string, userID string) ([]model.Vulnerability, error) {
	if f.expectedUserID != "" && userID != f.expectedUserID {
		return nil, assetrepo.ErrRecordNotFound
	}
	return f.asset.Vulnerabilities, f.findErr
}

// ExistsBySignatureForUser reports whether the fake duplicate exists.
func (f *fakeAssetRepository) ExistsBySignatureForUser(ec *appcontext.GinContext, asset model.Asset, userID string) (bool, error) {
	return f.signatureExists, nil
}

// CreateForUser returns the supplied fake asset.
func (f *fakeAssetRepository) CreateForUser(ec *appcontext.GinContext, userID string, asset model.Asset) (model.Asset, error) {
	if f.asset.ID != "" {
		asset.ID = f.asset.ID
	}
	asset.UserID = userID
	f.saved = asset
	return asset, nil
}

// UpdateForUser returns the supplied fake asset.
func (f *fakeAssetRepository) UpdateForUser(ec *appcontext.GinContext, id string, userID string, asset model.Asset) (model.Asset, error) {
	f.saved = asset
	return asset, nil
}

// DeleteForUser returns the configured fake asset.
func (f *fakeAssetRepository) DeleteForUser(ec *appcontext.GinContext, id string, userID string) (model.Asset, error) {
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

func (f *fakeVulnerabilityRepository) FindAffectedAssetsForUser(ec *appcontext.GinContext, vulnerabilityID string, userID string) ([]model.Asset, error) {
	return nil, nil
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

func (f *fakeVulnerabilityRepository) CreateForUser(ec *appcontext.GinContext, userID string, vulnerability model.Vulnerability) (model.Vulnerability, error) {
	f.saved = vulnerability
	f.saved.ID = "00000000-0000-4000-8000-000000000099"
	f.saved.UserID = userID
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

// newServiceContext creates a request context with an authenticated user ID.
func newServiceContext(t *testing.T, userID string) *appcontext.GinContext {
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
	return model.Asset{
		Name:        "Asset 1",
		Type:        "Server",
		Vendor:      stringPtr("Example Vendor"),
		Product:     stringPtr("Example Product"),
		Version:     stringPtr("1.0"),
		Owner:       "IT",
		Criticality: "High",
	}
}

func stringPtr(value string) *string {
	return &value
}
