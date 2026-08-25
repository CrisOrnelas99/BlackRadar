package health_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	nvdcveclient "blackradar/api/external/nvd_cve"
	servicehealth "blackradar/api/service/health"
	textgeneration "blackradar/api/service/text_generation"
	"github.com/gin-gonic/gin"

	"blackradar/api/controller/health"
)

func TestHealth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/health", health.Health)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	var response map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}
	if response["status"] != "ok" {
		t.Fatalf("expected status ok, got %q", response["status"])
	}
}

func TestSummaryIncludesNVDReadiness(t *testing.T) {
	gin.SetMode(gin.TestMode)
	nvdChecker := &fakeNVDReadinessChecker{}
	router := gin.New()
	router.GET("/health/summary", summaryHandler(fakeReadinessChecker{}, false, nil, nvdChecker))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/health/summary", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	var response struct {
		Overall string `json:"overall"`
		NVD     struct {
			Status string `json:"status"`
		} `json:"nvd"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode summary response: %v", err)
	}
	if response.Overall != "healthy" {
		t.Fatalf("expected healthy overall status, got %q", response.Overall)
	}
	if response.NVD.Status != "healthy" {
		t.Fatalf("expected healthy NVD status, got %q", response.NVD.Status)
	}
	if nvdChecker.cveID != "CVE-2021-44228" {
		t.Fatalf("expected fixed NVD health-check CVE ID, got %q", nvdChecker.cveID)
	}
}

func TestSummaryMarksNVDUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/health/summary", summaryHandler(fakeReadinessChecker{}, false, nil, &fakeNVDReadinessChecker{err: errors.New("nvd unavailable")}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/health/summary", nil)
	router.ServeHTTP(recorder, request)

	var response struct {
		Overall string `json:"overall"`
		NVD     struct {
			Status string `json:"status"`
		} `json:"nvd"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode summary response: %v", err)
	}
	if response.Overall != "unavailable" || response.NVD.Status != "unavailable" {
		t.Fatalf("expected unavailable NVD summary, got overall=%q nvd=%q", response.Overall, response.NVD.Status)
	}
}

func TestSummaryCachesProviderReadiness(t *testing.T) {
	gin.SetMode(gin.TestMode)
	aiChecker := &fakeAIReadinessChecker{}
	nvdChecker := &fakeNVDReadinessChecker{}
	router := gin.New()
	router.GET("/health/summary", summaryHandler(fakeReadinessChecker{}, true, aiChecker, nvdChecker))

	for range 2 {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/health/summary", nil)
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
		}
	}

	if aiChecker.calls != 1 {
		t.Fatalf("expected one AI readiness check, got %d", aiChecker.calls)
	}
	if nvdChecker.calls != 1 {
		t.Fatalf("expected one NVD readiness check, got %d", nvdChecker.calls)
	}
}

func summaryHandler(database servicehealth.DatabaseChecker, aiConfigured bool, ai servicehealth.AIReadinessChecker, nvd servicehealth.NVDReadinessChecker) gin.HandlerFunc {
	return health.Summary(servicehealth.NewSummaryChecker(servicehealth.Dependencies{
		Database:     database,
		AIConfigured: aiConfigured,
		AI:           ai,
		NVD:          nvd,
	}))
}

func TestReadyRejectsMissingDatabase(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/ready", health.Ready(nil))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/ready", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, recorder.Code)
	}

	var response map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode ready response: %v", err)
	}
	if response["status"] != "unavailable" {
		t.Fatalf("expected status unavailable, got %q", response["status"])
	}
}

func TestRegisterRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	health.RegisterRoutes(router, nil)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected health status %d, got %d", http.StatusOK, recorder.Code)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/api/ready", nil)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected ready status %d, got %d", http.StatusServiceUnavailable, recorder.Code)
	}
}

type fakeReadinessChecker struct{}

func (fakeReadinessChecker) Ping(context.Context) error {
	return nil
}

type fakeNVDReadinessChecker struct {
	err   error
	cveID string
	calls int
}

func (f *fakeNVDReadinessChecker) LookupCVE(_ context.Context, cveID string) (nvdcveclient.CVELookupResponse, error) {
	f.calls++
	f.cveID = cveID
	return nvdcveclient.CVELookupResponse{}, f.err
}

type fakeAIReadinessChecker struct {
	err   error
	calls int
}

func (f *fakeAIReadinessChecker) TestProvider(context.Context) (textgeneration.TextGenerationResponse, error) {
	f.calls++
	return textgeneration.TextGenerationResponse{}, f.err
}
