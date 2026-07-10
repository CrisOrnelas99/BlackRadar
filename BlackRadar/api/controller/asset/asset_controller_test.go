// Package controller tests asset controller request handling.
package controller

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	appcontext "blackradar/api/context"
	"blackradar/api/dto"
	"blackradar/api/model"
	baseservice "blackradar/api/service"
)

// TestAssetControllerHandlers verifies the asset controller request flow.
func TestAssetControllerHandlers(t *testing.T) {
	svc := &fakeAssetService{asset: sampleAsset(), assets: []model.Asset{sampleAsset()}}
	controller := NewAssetController(svc, &fakeAssetMatchService{asset: sampleAsset()})

	t.Run("get assets", func(t *testing.T) {
		ec, _ := newAssetContext(t, http.MethodGet, "/assets", "")
		controller.GetAssets(ec)
		if svc.getAllCalls != 1 {
			t.Fatal("expected GetAllAssets to be called")
		}
	})

	t.Run("create asset", func(t *testing.T) {
		ec, recorder := newAssetContext(t, http.MethodPost, "/assets", `{"name":"Asset 1","type":"Server","owner":"IT","criticality":"High"}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.CreateAsset(ec)
		if svc.createCalls != 1 {
			t.Fatal("expected CreateAsset to be called")
		}
		var response map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("failed to decode create asset response: %v", err)
		}
		if _, exists := response["riskScore"]; exists {
			t.Fatal("expected create asset response not to expose riskScore")
		}
		if _, exists := response["assetAssessmentId"]; !exists {
			t.Fatal("expected create asset response to expose assetAssessmentId")
		}
		if _, exists := response["riskLevel"]; !exists {
			t.Fatal("expected create asset response to expose riskLevel")
		}
		if response["riskLevel"] != nil {
			t.Fatalf("expected create asset response riskLevel to be null, got %#v", response["riskLevel"])
		}
	})

	t.Run("create asset with raw text does not auto-match vulnerabilities", func(t *testing.T) {
		svc := &fakeAssetService{asset: sampleAsset()}
		controller := NewAssetController(svc, &fakeAssetMatchService{asset: sampleAsset()})
		ec, _ := newAssetContext(t, http.MethodPost, "/assets", `{"name":"Asset 1","type":"Server","owner":"IT","criticality":"High","rawText":"Vendor: Tukaani\nProduct: xz\nVersion: 5.6.1"}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.CreateAsset(ec)
		if svc.createCalls != 1 {
			t.Fatalf("expected CreateAsset to be called once, got %d", svc.createCalls)
		}
	})

	t.Run("create asset from ai mode", func(t *testing.T) {
		ec, _ := newAssetContext(t, http.MethodPost, "/assets", `{"aiMode":true,"rawText":"I have an Amazon Ring doorbell running firmware 3.4.6."}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.CreateAsset(ec)
		if svc.createFromAICalls != 1 {
			t.Fatalf("expected CreateAssetFromAI to be called once, got %d", svc.createFromAICalls)
		}
	})

	t.Run("match asset cpe and attach vulnerabilities", func(t *testing.T) {
		matchSvc := &fakeAssetMatchService{asset: sampleAsset()}
		controller := NewAssetController(svc, matchSvc)
		ec, recorder := newAssetContext(t, http.MethodPost, "/assets/00000000-0000-4000-8000-000000000001/match-cpe/vulnerabilities", "")
		ec.AddParam("id", "00000000-0000-4000-8000-000000000001")
		controller.MatchAssetCPEAndAttachVulnerabilities(ec)
		if matchSvc.attachCalls != 1 {
			t.Fatalf("expected AnalyzePersistAndAttachVulnerabilities to be called once, got %d", matchSvc.attachCalls)
		}
		var response map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("failed to decode match-and-attach response: %v", err)
		}
		assetValue, exists := response["asset"].(map[string]any)
		if !exists {
			t.Fatal("expected match-and-attach response to include nested asset object")
		}
		if _, exists := assetValue["vulnerabilities"]; !exists {
			t.Fatal("expected nested asset object to include vulnerabilities")
		}
	})
}

type fakeAssetService struct {
	assets            []model.Asset
	asset             model.Asset
	err               error
	getAllCalls       int
	createCalls       int
	createFromAICalls int
}

type fakeAssetMatchService struct {
	asset       model.Asset
	err         error
	calls       int
	attachCalls int
}

func (f *fakeAssetMatchService) AnalyzeAndPersistAssetMatch(ec *appcontext.GinContext, assetID string) (model.Asset, error) {
	f.calls++
	return f.asset, f.err
}

func (f *fakeAssetMatchService) AnalyzePersistAndAttachVulnerabilities(ec *appcontext.GinContext, assetID string) (model.Asset, error) {
	f.attachCalls++
	return f.asset, f.err
}

func (f *fakeAssetService) GetAllAssets(ec *appcontext.GinContext) ([]model.Asset, error) {
	f.getAllCalls++
	return f.assets, f.err
}
func (f *fakeAssetService) GetAsset(ec *appcontext.GinContext, id string) (model.Asset, error) {
	return f.asset, f.err
}
func (f *fakeAssetService) CreateAsset(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error) {
	f.createCalls++
	return f.asset, f.err
}
func (f *fakeAssetService) CreateAssetFromAI(ec *appcontext.GinContext, rawText string) (model.Asset, error) {
	f.createFromAICalls++
	return f.asset, f.err
}
func (f *fakeAssetService) UpdateAsset(ec *appcontext.GinContext, id string, asset model.Asset) (model.Asset, error) {
	return f.asset, f.err
}
func (f *fakeAssetService) DeleteAsset(ec *appcontext.GinContext, id string) (model.Asset, error) {
	return f.asset, f.err
}
func (f *fakeAssetService) AssignVulnerability(ec *appcontext.GinContext, assetID string, vulnerabilityID string) (model.Asset, error) {
	return f.asset, f.err
}
func (f *fakeAssetService) AssignVulnerabilityByCVE(ec *appcontext.GinContext, assetID string, cveID string) (model.Asset, error) {
	return f.asset, f.err
}
func (f *fakeAssetService) RemoveVulnerability(ec *appcontext.GinContext, assetID string, vulnerabilityID string) (model.Asset, error) {
	return f.asset, f.err
}

var _ baseservice.AssetService = (*fakeAssetService)(nil)

// newAssetContext creates a test Gin context for asset controller tests.
func newAssetContext(t *testing.T, method string, target string, body string) (*appcontext.GinContext, *httptest.ResponseRecorder) {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(method, target, nil)
	if body != "" {
		req.Body = io.NopCloser(strings.NewReader(body))
	}
	ctx.Request = req
	ec := appcontext.NewGinContext(ctx, "txn-123", nil)
	appcontext.SetGinContext(ctx, ec)
	return ec, recorder
}

// sampleAsset returns a reusable asset fixture.
func sampleAsset() model.Asset {
	assessmentID := "00000000-0000-4000-8000-000000000009"
	return model.Asset{
		Model:             model.Model{ID: "00000000-0000-4000-8000-000000000001"},
		AssetAssessmentID: &assessmentID,
		Name:              "Asset 1",
		Type:              "Server",
		Owner:             "IT",
		Criticality:       "High",
		Vulnerabilities: []model.Vulnerability{
			{Model: model.Model{ID: "00000000-0000-4000-8000-000000000010"}, CVEID: "CVE-2026-0001", Title: "Issue", Severity: "High", Description: "desc", Status: "Open"},
		},
		Assessment: &model.AssetAssessment{
			Model:           model.Model{ID: assessmentID},
			RiskScore:       12,
			CPEReviewStatus: model.AssetCPEReviewStatusNeedsReview,
		},
	}
}

var _ = errors.New
var _ = dto.AssetRequest{}
