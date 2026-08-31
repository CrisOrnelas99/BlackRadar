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
	"time"

	"github.com/gin-gonic/gin"

	"blackradar/api/common/pagination"
	contextmiddleware "blackradar/api/middleware/context"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
	assetservice "blackradar/api/service/asset"
	assetmatchservice "blackradar/api/service/asset_match"
	assetvulnerabilityservice "blackradar/api/service/asset_vulnerability"
)

// TestAssetControllerHandlers verifies the asset controller request flow.
func TestAssetControllerHandlers(t *testing.T) {
	svc := &fakeAssetService{asset: sampleAsset(), assets: []model.Asset{sampleAsset()}}
	assetVulnerabilitySvc := &fakeAssetVulnerabilityService{asset: sampleAsset()}
	controller := NewAssetController(svc, assetVulnerabilitySvc, &fakeAssetMatchService{asset: sampleAsset()})

	t.Run("get assets", func(t *testing.T) {
		ec, _ := newAssetContext(t, http.MethodGet, "/assets", "")
		controller.GetAssets(ec)
		if svc.getPageCalls != 1 {
			t.Fatal("expected GetAssetPage to be called")
		}
	})

	t.Run("get paged assets", func(t *testing.T) {
		ec, recorder := newAssetContext(t, http.MethodGet, "/assets?page=2&search=server&criticality=High&vulnerabilityMode=atLeast&vulnerabilityValue=2&sortField=vulnerabilityCount&sortDirection=desc", "")
		controller.GetAssets(ec)
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
		}
		var response AssetPageResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("failed to decode paged response: %v", err)
		}
		if response.Pagination.Page != 2 || response.Pagination.PageSize != pagination.DefaultPageSize || response.Pagination.TotalCount != 1 {
			t.Fatalf("unexpected paged response: %+v", response)
		}
		if len(response.Assets) != 1 {
			t.Fatalf("expected one asset in the paged response, got %d", len(response.Assets))
		}
		if svc.lastListQuery.Pagination.Page != 2 || svc.lastListQuery.Search != "server" || svc.lastListQuery.Criticality != "High" || svc.lastListQuery.SortField != "vulnerabilityCount" || svc.lastListQuery.VulnerabilityValue == nil || *svc.lastListQuery.VulnerabilityValue != 2 {
			t.Fatalf("unexpected asset list query: %+v", svc.lastListQuery)
		}
	})

	t.Run("reject malformed pagination query", func(t *testing.T) {
		ec, recorder := newAssetContext(t, http.MethodGet, "/assets?page=invalid", "")
		controller.GetAssets(ec)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
		}
	})

	t.Run("get asset summary", func(t *testing.T) {
		svc.summary = model.AssetSummary{TotalCount: 3, WithVulnerabilitiesCount: 2}
		ec, recorder := newAssetContext(t, http.MethodGet, "/assets/summary", "")
		controller.GetAssetSummary(ec)
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
		}
		var response AssetSummaryResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("failed to decode summary response: %v", err)
		}
		if response.TotalCount != 3 || response.WithVulnerabilitiesCount != 2 {
			t.Fatalf("unexpected Asset summary: %+v", response)
		}
	})

	t.Run("get asset vulnerabilities", func(t *testing.T) {
		attachedAsset := sampleAsset()
		attachedVulnerabilities := []model.Vulnerability{{Model: model.Model{ID: "vulnerability-2"}, Title: "Returned vulnerability", Severity: "Critical", Status: "Open"}}
		assetService := &fakeAssetService{asset: attachedAsset, vulnerabilities: attachedVulnerabilities}
		controller := NewAssetController(
			assetService,
			assetVulnerabilitySvc,
			&fakeAssetMatchService{asset: attachedAsset},
		)
		assetID := "00000000-0000-4000-8000-000000000001"
		ec, recorder := newAssetContext(t, http.MethodGet, "/assets/"+assetID+"/vulnerabilities", "")
		ec.AddParam("id", assetID)

		controller.GetAssetVulnerabilities(ec)

		if recorder.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
		}
		var response AssetWithVulnerabilitiesResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if assetService.getAssetVulnerabilitiesCalls != 1 {
			t.Fatalf("expected GetAssetVulnerabilities to be called once, got %d", assetService.getAssetVulnerabilitiesCalls)
		}
		if assetService.getAssetVulnerabilitiesID != assetID {
			t.Fatalf("expected GetAssetVulnerabilities to receive %q, got %q", assetID, assetService.getAssetVulnerabilitiesID)
		}
		if len(response.Vulnerabilities) != 1 || response.Vulnerabilities[0].ID != "vulnerability-2" {
			t.Fatalf("expected attached vulnerability in response, got %+v", response.Vulnerabilities)
		}
	})

	t.Run("create asset", func(t *testing.T) {
		svc.asset.RiskLevel = stringPtr("Low")
		ec, recorder := newAssetContext(t, http.MethodPost, "/assets", `{"name":"Asset 1","type":"Server","vendor":"Example Vendor","product":"Example Product","version":"1.0","criticality":"High"}`)
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
		if response["riskLevel"] != "Low" {
			t.Fatalf("expected create asset response riskLevel to be Low, got %#v", response["riskLevel"])
		}
	})

	t.Run("rejects removed ai asset creation mode", func(t *testing.T) {
		svc := &fakeAssetService{asset: sampleAsset()}
		controller := NewAssetController(svc, assetVulnerabilitySvc, &fakeAssetMatchService{asset: sampleAsset()})
		ec, recorder := newAssetContext(t, http.MethodPost, "/assets", `{"aiMode":true,"rawText":"Create an asset from this text."}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.CreateAsset(ec)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("expected removed AI mode to be rejected with bad request, got %d", recorder.Code)
		}
		if svc.createCalls != 0 {
			t.Fatal("expected removed AI mode not to create an asset")
		}
	})

	t.Run("apply approved asset cpe match", func(t *testing.T) {
		matchSvc := &fakeAssetMatchService{asset: sampleAsset()}
		controller := NewAssetController(svc, assetVulnerabilitySvc, matchSvc)
		ec, recorder := newAssetContext(t, http.MethodPost, "/assets/00000000-0000-4000-8000-000000000001/match-cpe/vulnerabilities/apply", `{"selectedCpe":"cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*"}`)
		ec.AddParam("id", "00000000-0000-4000-8000-000000000001")
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.ApplyAssetCPEMatch(ec)
		if matchSvc.applyCalls != 1 {
			t.Fatalf("expected ApplyApprovedCPEMatch to be called once, got %d", matchSvc.applyCalls)
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

func TestRegisterRoutes(t *testing.T) {
	service := &fakeAssetService{asset: sampleAsset(), assets: []model.Asset{sampleAsset()}}
	assetVulnerabilityService := &fakeAssetVulnerabilityService{asset: sampleAsset()}
	assetMatchService := &fakeAssetMatchService{asset: sampleAsset()}
	controller := NewAssetController(service, assetVulnerabilityService, assetMatchService)
	engine := gin.New()
	engine.Use(contextmiddleware.RequestContext(nil))
	group := engine.Group("/api")
	RegisterRoutes(group, group, controller)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/assets", nil)
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected assets status %d, got %d", http.StatusOK, recorder.Code)
	}
	if service.getPageCalls != 1 {
		t.Fatalf("expected GetAssetPage to be called once, got %d", service.getPageCalls)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequestWithContext(request.Context(), http.MethodGet, "/api/assets/summary", nil)
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected Asset summary status %d, got %d", http.StatusOK, recorder.Code)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/api/assets/00000000-0000-4000-8000-000000000001/match-cpe/vulnerabilities/apply", strings.NewReader(`{"selectedCpe":"cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*"}`))
	request.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected match status %d, got %d", http.StatusOK, recorder.Code)
	}
	if assetMatchService.applyCalls != 1 {
		t.Fatalf("expected ApplyApprovedCPEMatch to be called once, got %d", assetMatchService.applyCalls)
	}
}

func TestToAssetResponseDTOIncludesMatchMetadata(t *testing.T) {
	assessmentID := "00000000-0000-4000-8000-000000000055"
	matchedAt := time.Date(2026, time.January, 12, 10, 30, 0, 0, time.UTC)
	productFingerprint := "vendor=dell;product=latitude 7420;version=1.2"
	selectedCPE := "cpe:2.3:a:dell:latitude_7420:1.2:*:*:*:*:*:*:*"
	confidence := 0.91
	reviewNotes := "strong vendor/product/version match"
	riskScore := int16(72)

	response := ToAssetResponseDTO(model.Asset{
		Model:             model.Model{ID: "00000000-0000-4000-8000-000000000007"},
		AssetAssessmentID: &assessmentID,
		Name:              "Asset 1",
		Type:              "Server",
		Owner:             "IT",
		Criticality:       "High",
		RiskLevel:         stringPtr("Low"),
		Assessment: &model.AssetAssessment{
			RiskScore:          riskScore,
			ProductFingerprint: &productFingerprint,
			SelectedCPE:        &selectedCPE,
			CPEConfidence:      &confidence,
			CPEReviewNotes:     &reviewNotes,
			CPECandidateCount:  4,
			CPEMatchedAt:       &matchedAt,
		},
	})

	if response.AssetAssessmentID == nil || *response.AssetAssessmentID != assessmentID {
		t.Fatalf("expected asset assessment id %s, got %#v", assessmentID, response.AssetAssessmentID)
	}
	if response.RiskLevel == nil || *response.RiskLevel != "Low" {
		t.Fatalf("expected Low risk level, got %#v", response.RiskLevel)
	}
	if !response.HasCVEScan {
		t.Fatal("expected selected CPE to mark the asset as CVE scanned")
	}
	if ToAssetResponseDTO(model.Asset{}).HasCVEScan {
		t.Fatal("expected asset without a selected CPE to remain unscanned")
	}
}

func TestToAssetMatchResponseDTOSeparatesAssessmentMetadata(t *testing.T) {
	assessmentID := "00000000-0000-4000-8000-000000000055"
	matchedAt := time.Date(2026, time.January, 12, 10, 30, 0, 0, time.UTC)
	productFingerprint := "vendor=dell;product=latitude 7420;version=1.2"
	selectedCPE := "cpe:2.3:a:dell:latitude_7420:1.2:*:*:*:*:*:*:*"
	confidence := 0.91
	reviewNotes := "strong vendor/product/version match"
	riskScore := int16(72)
	assessmentCreatedAt := time.Date(2026, time.January, 11, 10, 30, 0, 0, time.UTC)
	assessmentUpdatedAt := time.Date(2026, time.January, 12, 10, 31, 0, 0, time.UTC)

	response := ToAssetMatchResponseDTO(model.Asset{
		Model:             model.Model{ID: "00000000-0000-4000-8000-000000000007"},
		AssetAssessmentID: &assessmentID,
		Name:              "Asset 1",
		Type:              "Server",
		Owner:             "IT",
		Criticality:       "High",
		RiskLevel:         stringPtr("Critical"),
		Vulnerabilities: []model.Vulnerability{
			{Model: model.Model{ID: "00000000-0000-4000-8000-000000000009"}, CVEID: "CVE-2026-0001", Title: "Issue", Severity: "High", Description: "desc", Status: "Open"},
		},
		Assessment: &model.AssetAssessment{
			Model:              model.Model{ID: assessmentID, CreatedAt: assessmentCreatedAt, UpdatedAt: assessmentUpdatedAt},
			RiskScore:          riskScore,
			ProductFingerprint: &productFingerprint,
			SelectedCPE:        &selectedCPE,
			CPEConfidence:      &confidence,
			CPEReviewNotes:     &reviewNotes,
			CPECandidateCount:  4,
			CPEMatchedAt:       &matchedAt,
		},
	})

	if response.Asset.AssetAssessmentID == nil || *response.Asset.AssetAssessmentID != assessmentID {
		t.Fatalf("expected nested asset assessment id %s, got %#v", assessmentID, response.Asset.AssetAssessmentID)
	}
	if len(response.Asset.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(response.Asset.Vulnerabilities))
	}
	if response.Asset.RiskLevel == nil || *response.Asset.RiskLevel != "Critical" {
		t.Fatalf("expected nested asset risk level Critical, got %#v", response.Asset.RiskLevel)
	}
	if response.AssetAssessment.ID == nil || *response.AssetAssessment.ID != assessmentID {
		t.Fatalf("expected assessment id %s, got %#v", assessmentID, response.AssetAssessment.ID)
	}
	if response.AssetAssessment.CPEReviewStatus != model.AssetCPEReviewStatusNeedsReview {
		t.Fatalf("expected default review status %q, got %q", model.AssetCPEReviewStatusNeedsReview, response.AssetAssessment.CPEReviewStatus)
	}
	if response.AssetAssessment.RiskScore != riskScore {
		t.Fatalf("expected risk score %d, got %d", riskScore, response.AssetAssessment.RiskScore)
	}
	if response.AssetAssessment.ProductFingerprint == nil || *response.AssetAssessment.ProductFingerprint != productFingerprint {
		t.Fatalf("expected product fingerprint %q, got %#v", productFingerprint, response.AssetAssessment.ProductFingerprint)
	}
	if response.AssetAssessment.SelectedCPE == nil || *response.AssetAssessment.SelectedCPE != selectedCPE {
		t.Fatalf("expected selected CPE %q, got %#v", selectedCPE, response.AssetAssessment.SelectedCPE)
	}
	if response.AssetAssessment.CPEConfidence == nil || *response.AssetAssessment.CPEConfidence != confidence {
		t.Fatalf("expected confidence %v, got %#v", confidence, response.AssetAssessment.CPEConfidence)
	}
	if response.AssetAssessment.CPEReviewNotes == nil || *response.AssetAssessment.CPEReviewNotes != reviewNotes {
		t.Fatalf("expected review notes %q, got %#v", reviewNotes, response.AssetAssessment.CPEReviewNotes)
	}
	if response.AssetAssessment.CPECandidateCount != 4 {
		t.Fatalf("expected candidate count 4, got %d", response.AssetAssessment.CPECandidateCount)
	}
	if response.AssetAssessment.CPEMatchedAt == nil || !response.AssetAssessment.CPEMatchedAt.Equal(matchedAt) {
		t.Fatalf("expected matched at %v, got %#v", matchedAt, response.AssetAssessment.CPEMatchedAt)
	}
	if response.AssetAssessment.CreatedAt == nil || !response.AssetAssessment.CreatedAt.Equal(assessmentCreatedAt) {
		t.Fatalf("expected assessment created at %v, got %#v", assessmentCreatedAt, response.AssetAssessment.CreatedAt)
	}
	if response.AssetAssessment.UpdatedAt == nil || !response.AssetAssessment.UpdatedAt.Equal(assessmentUpdatedAt) {
		t.Fatalf("expected assessment updated at %v, got %#v", assessmentUpdatedAt, response.AssetAssessment.UpdatedAt)
	}
}

func TestToAssetMatchPreviewResponseDTOAlwaysReturnsCVEIDsArray(t *testing.T) {
	response := ToAssetMatchPreviewResponseDTO(assetmatchservice.AssetMatchPreview{})
	if response.CVEIDs == nil {
		t.Fatal("expected CVE IDs to be an empty slice")
	}

	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("failed to encode match preview response: %v", err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("failed to decode match preview response: %v", err)
	}
	if string(payload["cveIds"]) != "[]" {
		t.Fatalf("expected cveIds to encode as an empty array, got %s", payload["cveIds"])
	}

	response = ToAssetMatchPreviewResponseDTO(assetmatchservice.AssetMatchPreview{
		CVEIDs: []string{"CVE-2026-0001"},
	})
	if len(response.CVEIDs) != 1 || response.CVEIDs[0] != "CVE-2026-0001" {
		t.Fatalf("expected CVE IDs to be preserved, got %#v", response.CVEIDs)
	}
}

func TestToAssetAssessmentResponseDTODefaultsWithoutAssessment(t *testing.T) {
	assessmentID := "00000000-0000-4000-8000-000000000077"
	response := ToAssetAssessmentResponseDTO(model.Asset{
		AssetAssessmentID: &assessmentID,
	})

	if response.ID == nil || *response.ID != assessmentID {
		t.Fatalf("expected assessment id %s, got %#v", assessmentID, response.ID)
	}
	if response.RiskScore != 0 {
		t.Fatalf("expected default risk score 0, got %d", response.RiskScore)
	}
	if response.CPEReviewStatus != model.AssetCPEReviewStatusNeedsReview {
		t.Fatalf("expected default review status %q, got %q", model.AssetCPEReviewStatusNeedsReview, response.CPEReviewStatus)
	}
}

type fakeAssetService struct {
	assets                       []model.Asset
	asset                        model.Asset
	vulnerabilities              []model.Vulnerability
	err                          error
	getPageCalls                 int
	lastListQuery                model.AssetListQuery
	summary                      model.AssetSummary
	createCalls                  int
	getAssetVulnerabilitiesCalls int
	getAssetVulnerabilitiesID    string
}

type fakeAssetVulnerabilityService struct {
	asset model.Asset
	err   error
}

type fakeAssetMatchService struct {
	asset        model.Asset
	err          error
	calls        int
	previewCalls int
	applyCalls   int
}

func (f *fakeAssetMatchService) PreviewAssetMatch(ec *appcontext.GinContext, assetID string, selectedCPE string) (assetmatchservice.AssetMatchPreview, error) {
	f.previewCalls++
	return assetmatchservice.AssetMatchPreview{}, f.err
}

func (f *fakeAssetMatchService) ApplyApprovedCPEMatch(ec *appcontext.GinContext, assetID string, selectedCPE string) (model.Asset, error) {
	f.applyCalls++
	return f.asset, f.err
}

func (f *fakeAssetService) GetAssetPage(ec *appcontext.GinContext, query model.AssetListQuery) (pagination.Page[model.Asset], error) {
	f.getPageCalls++
	f.lastListQuery = query
	return pagination.Page[model.Asset]{Items: f.assets, Page: query.Pagination.Page, PageSize: pagination.DefaultPageSize, TotalCount: int64(len(f.assets))}, f.err
}
func (f *fakeAssetService) GetAssetSummary(ec *appcontext.GinContext) (model.AssetSummary, error) {
	return f.summary, f.err
}
func (f *fakeAssetService) GetAsset(ec *appcontext.GinContext, id string) (model.Asset, error) {
	return f.asset, f.err
}
func (f *fakeAssetService) GetAssetVulnerabilities(ec *appcontext.GinContext, id string) ([]model.Vulnerability, error) {
	f.getAssetVulnerabilitiesCalls++
	f.getAssetVulnerabilitiesID = id
	return f.vulnerabilities, f.err
}
func (f *fakeAssetService) CreateAsset(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error) {
	f.createCalls++
	return f.asset, f.err
}
func (f *fakeAssetService) UpdateAsset(ec *appcontext.GinContext, id string, asset model.Asset) (model.Asset, error) {
	return f.asset, f.err
}
func (f *fakeAssetService) DeleteAsset(ec *appcontext.GinContext, id string) (model.Asset, error) {
	return f.asset, f.err
}

func (f *fakeAssetVulnerabilityService) AssignVulnerability(ec *appcontext.GinContext, assetID string, vulnerabilityID string) (model.Asset, error) {
	return f.asset, f.err
}
func (f *fakeAssetVulnerabilityService) RemoveVulnerability(ec *appcontext.GinContext, assetID string, vulnerabilityID string) (model.Asset, error) {
	return f.asset, f.err
}

var _ assetservice.AssetService = (*fakeAssetService)(nil)
var _ assetvulnerabilityservice.AssetVulnerabilityService = (*fakeAssetVulnerabilityService)(nil)
var _ assetmatchservice.AssetMatchService = (*fakeAssetMatchService)(nil)

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

func stringPtr(value string) *string {
	return &value
}

var _ = errors.New
var _ = AssetRequest{}
