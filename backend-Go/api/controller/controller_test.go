// Package controller_test verifies controller helpers, health checks, and route registration.
package controller_test

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	appcontext "secureops/backend-go/api/context"
	basecontroller "secureops/backend-go/api/controller"
	controllerasset "secureops/backend-go/api/controller/asset"
	controllerauth "secureops/backend-go/api/controller/auth"
	controllervulnerability "secureops/backend-go/api/controller/vulnerability"
	"secureops/backend-go/api/dto"
	"secureops/backend-go/api/middleware"
	"secureops/backend-go/api/model"
	baserepository "secureops/backend-go/api/repository"
	"secureops/backend-go/api/security"
	"secureops/backend-go/api/service"
)

// TestMain sets Gin into test mode for controller tests.
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

// TestControllerHelper verifies the shared controller helper functions.
func TestControllerHelper(t *testing.T) {
	t.Run("parse id", func(t *testing.T) {
		id, err := basecontroller.ParseID("42")
		if err != nil {
			t.Fatalf("expected id to parse, got %v", err)
		}
		if id != 42 {
			t.Fatalf("expected 42, got %d", id)
		}
	})

	t.Run("bind json", func(t *testing.T) {
		ec, recorder := newControllerContext(t, http.MethodPost, "/assets", `{"name":"Asset 1","type":"Server","ipAddress":"192.168.1.10","owner":"IT","criticality":"High"}`)
		ec.Request.Header.Set("Content-Type", "application/json")

		var request dto.AssetRequest
		if handled := basecontroller.BindJSON(ec, &request); handled {
			t.Fatal("expected request to bind")
		}
		if request.Name != "Asset 1" {
			t.Fatalf("expected Asset 1, got %q", request.Name)
		}
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected no error response, got %d", recorder.Code)
		}
	})

	t.Run("handle error", func(t *testing.T) {
		ec, recorder := newControllerContext(t, http.MethodGet, "/resource", "")
		if !basecontroller.HandleError(ec, http.StatusBadRequest, errors.New("boom"), "Invalid request body") {
			t.Fatal("expected error to be handled")
		}

		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
		}

		var response dto.ErrorResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("failed to decode error response: %v", err)
		}
		if response.Code != "VALIDATION_ERROR" {
			t.Fatalf("expected validation error code, got %q", response.Code)
		}
	})
}

// TestHealth verifies the health endpoint returns success.
func TestHealth(t *testing.T) {
	router := gin.New()
	router.GET("/api/health", basecontroller.Health)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

// TestRegisterRoutes verifies the route registration wiring.
func TestRegisterRoutes(t *testing.T) {
	engine := gin.New()
	jwtManager := security.NewJWTManager("test-secret", time.Hour, time.Hour*24, "issuer", "audience")
	lookup := &fakeUserLookup{exists: true, user: model.User{ID: 1, Username: "analyst", Role: model.RoleAdmin}}
	sessions := &fakeRefreshSessionLookup{session: model.RefreshSession{TokenID: "session-1", UserID: 1}}

	authController := controllerauth.NewAuthController(&fakeAuthService{})
	assetController := controllerasset.NewAssetController(&fakeAssetService{asset: sampleAsset(), assets: []model.Asset{sampleAsset()}})
	vulnerabilityController := controllervulnerability.NewVulnerabilityController(&fakeVulnerabilityService{vulnerability: sampleVulnerability(), vulnerabilities: []model.Vulnerability{sampleVulnerability()}})
	nvdLookupCalled := false

	basecontroller.RegisterRoutes(engine, jwtManager, lookup, sessions, basecontroller.RouteHandlers{
		RegisterAuth:             authController.Register,
		LoginAuth:                authController.Login,
		RefreshAuth:              authController.Refresh,
		LogoutAuth:               authController.Logout,
		GetAssets:                assetController.GetAssets,
		GetAsset:                 assetController.GetAsset,
		CreateAsset:              assetController.CreateAsset,
		UpdateAsset:              assetController.UpdateAsset,
		DeleteAsset:              assetController.DeleteAsset,
		AssignVulnerability:      assetController.AssignVulnerability,
		AssignVulnerabilityByCVE: assetController.AssignVulnerabilityByCVE,
		RemoveVulnerability:      assetController.RemoveVulnerability,
		GetVulnerabilities:       vulnerabilityController.GetVulnerabilities,
		GetVulnerability:         vulnerabilityController.GetVulnerability,
		CreateVulnerability:      vulnerabilityController.CreateVulnerability,
		UpdateVulnerability:      vulnerabilityController.UpdateVulnerability,
		DeleteVulnerability:      vulnerabilityController.DeleteVulnerability,
		LookupCVE: func(ec *appcontext.GinContext) {
			nvdLookupCalled = true
			ec.JSON(http.StatusOK, gin.H{"cveId": ec.Param("cveId")})
		},
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected health endpoint to be registered, got %d", recorder.Code)
	}

	token, err := jwtManager.GenerateToken("analyst", "session-1")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/api/nvd/cves/CVE-2021-44228", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected NVD route status %d, got %d", http.StatusOK, recorder.Code)
	}
	if !nvdLookupCalled {
		t.Fatal("expected NVD lookup route handler to be called")
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/api/auth/refresh", strings.NewReader(`{"refreshToken":"refresh"}`))
	request.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected auth refresh route status %d, got %d", http.StatusOK, recorder.Code)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/api/auth/logout", strings.NewReader(`{"refreshToken":"refresh"}`))
	request.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected auth logout route status %d, got %d", http.StatusOK, recorder.Code)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/api/assets/1/vulnerabilities/cve/CVE-2024-3094", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected CVE assignment route status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestRegisterRoutesRejectsVulnerabilityRoutesForNonAdmin(t *testing.T) {
	engine := gin.New()
	jwtManager := security.NewJWTManager("test-secret", time.Hour, time.Hour*24, "issuer", "audience")
	lookup := &fakeUserLookup{exists: true, user: model.User{ID: 1, Username: "analyst", Role: model.RoleUser}}
	sessions := &fakeRefreshSessionLookup{session: model.RefreshSession{TokenID: "session-1", UserID: 1}}

	vulnerabilityController := controllervulnerability.NewVulnerabilityController(&fakeVulnerabilityService{vulnerability: sampleVulnerability(), vulnerabilities: []model.Vulnerability{sampleVulnerability()}})

	basecontroller.RegisterRoutes(engine, jwtManager, lookup, sessions, basecontroller.RouteHandlers{
		GetVulnerabilities:  vulnerabilityController.GetVulnerabilities,
		GetVulnerability:    vulnerabilityController.GetVulnerability,
		CreateVulnerability: vulnerabilityController.CreateVulnerability,
		UpdateVulnerability: vulnerabilityController.UpdateVulnerability,
		DeleteVulnerability: vulnerabilityController.DeleteVulnerability,
		LookupCVE: func(ec *appcontext.GinContext) {
			ec.JSON(http.StatusOK, gin.H{"cveId": ec.Param("cveId")})
		},
	})

	token, err := jwtManager.GenerateToken("analyst", "session-1")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/vulnerabilities", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected vulnerability route to be forbidden, got %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/api/nvd/cves/CVE-2021-44228", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected NVD route to be forbidden, got %d", recorder.Code)
	}
}

type fakeUserLookup struct {
	exists bool
	user   model.User
}

// ExistsByUsername reports whether the fake user exists.
func (f *fakeUserLookup) ExistsByUsername(ec *appcontext.GinContext, username string) (bool, error) {
	return f.exists, nil
}

// FindByUsername returns the fake user record.
func (f *fakeUserLookup) FindByUsername(ec *appcontext.GinContext, username string) (model.User, error) {
	return f.user, nil
}

type fakeRefreshSessionLookup struct {
	session model.RefreshSession
}

func (f *fakeRefreshSessionLookup) FindActiveByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID int64) (model.RefreshSession, error) {
	if f.session.TokenID == tokenID && f.session.UserID == userID {
		return f.session, nil
	}
	return model.RefreshSession{}, baserepository.ErrRefreshSessionNotFound
}

type fakeAuthService struct{}

// Register simulates a successful auth registration.
func (f *fakeAuthService) Register(ec *appcontext.GinContext, request dto.RegisterRequest) error {
	return nil
}

// Login simulates a successful auth login.
func (f *fakeAuthService) Login(ec *appcontext.GinContext, request dto.LoginRequest) (dto.LoginResponse, error) {
	return dto.LoginResponse{}, nil
}

// Refresh simulates a successful auth refresh.
func (f *fakeAuthService) Refresh(ec *appcontext.GinContext, request dto.RefreshRequest) (dto.LoginResponse, error) {
	return dto.LoginResponse{}, nil
}

// Logout simulates a successful auth logout.
func (f *fakeAuthService) Logout(ec *appcontext.GinContext, request dto.RefreshRequest) error {
	return nil
}

type fakeAssetService struct {
	assets []model.Asset
	asset  model.Asset
}

// GetAllAssets returns the configured fake assets.
func (f *fakeAssetService) GetAllAssets(ec *appcontext.GinContext) ([]model.Asset, error) {
	return f.assets, nil
}

// GetAsset returns the configured fake asset.
func (f *fakeAssetService) GetAsset(ec *appcontext.GinContext, id int64) (model.Asset, error) {
	return f.asset, nil
}

// CreateAsset returns the configured fake asset.
func (f *fakeAssetService) CreateAsset(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error) {
	return f.asset, nil
}

// UpdateAsset returns the configured fake asset.
func (f *fakeAssetService) UpdateAsset(ec *appcontext.GinContext, id int64, asset model.Asset) (model.Asset, error) {
	return f.asset, nil
}

// DeleteAsset returns the configured fake asset.
func (f *fakeAssetService) DeleteAsset(ec *appcontext.GinContext, id int64) (model.Asset, error) {
	return f.asset, nil
}

// AssignVulnerability returns the configured fake asset.
func (f *fakeAssetService) AssignVulnerability(ec *appcontext.GinContext, assetID int64, vulnerabilityID int64) (model.Asset, error) {
	return f.asset, nil
}

// AssignVulnerabilityByCVE returns the configured fake asset.
func (f *fakeAssetService) AssignVulnerabilityByCVE(ec *appcontext.GinContext, assetID int64, cveID string) (model.Asset, error) {
	return f.asset, nil
}

// RemoveVulnerability returns the configured fake asset.
func (f *fakeAssetService) RemoveVulnerability(ec *appcontext.GinContext, assetID int64, vulnerabilityID int64) (model.Asset, error) {
	return f.asset, nil
}

type fakeVulnerabilityService struct {
	vulnerabilities []model.Vulnerability
	vulnerability   model.Vulnerability
}

// GetAllVulnerabilities returns the configured fake vulnerabilities.
func (f *fakeVulnerabilityService) GetAllVulnerabilities(ec *appcontext.GinContext) ([]model.Vulnerability, error) {
	return f.vulnerabilities, nil
}

// GetVulnerability returns the configured fake vulnerability.
func (f *fakeVulnerabilityService) GetVulnerability(ec *appcontext.GinContext, id int64) (model.Vulnerability, error) {
	return f.vulnerability, nil
}

// CreateVulnerability returns the configured fake vulnerability.
func (f *fakeVulnerabilityService) CreateVulnerability(ec *appcontext.GinContext, vulnerability model.Vulnerability) (model.Vulnerability, error) {
	return f.vulnerability, nil
}

// UpdateVulnerability returns the configured fake vulnerability.
func (f *fakeVulnerabilityService) UpdateVulnerability(ec *appcontext.GinContext, id int64, vulnerability model.Vulnerability) (model.Vulnerability, error) {
	return f.vulnerability, nil
}

// DeleteVulnerability returns the configured fake vulnerability.
func (f *fakeVulnerabilityService) DeleteVulnerability(ec *appcontext.GinContext, id int64) (model.Vulnerability, error) {
	return f.vulnerability, nil
}

var _ middleware.UserLookup = (*fakeUserLookup)(nil)
var _ service.AuthService = (*fakeAuthService)(nil)
var _ service.AssetService = (*fakeAssetService)(nil)
var _ service.VulnerabilityService = (*fakeVulnerabilityService)(nil)

// newControllerContext creates a test Gin context and recorder.
func newControllerContext(t *testing.T, method string, target string, body string) (*appcontext.GinContext, *httptest.ResponseRecorder) {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	ctx.Request = httptest.NewRequest(method, target, reader)
	if body == "" {
		ctx.Request.Body = http.NoBody
	}
	ec := appcontext.NewGinContext(ctx, "txn-123", log.New(io.Discard, "", 0))
	appcontext.SetGinContext(ctx, ec)
	return ec, recorder
}

// sampleAsset returns a reusable asset fixture.
func sampleAsset() model.Asset {
	return model.Asset{ID: 1, Name: "Asset 1", Type: "Server", IPAddress: "10.0.0.10", Owner: "IT", Criticality: "High"}
}

// sampleVulnerability returns a reusable vulnerability fixture.
func sampleVulnerability() model.Vulnerability {
	return model.Vulnerability{ID: 1, CVEID: "CVE-2026-0001", Title: "Issue", Severity: "High", Description: "desc", Status: "Open"}
}
