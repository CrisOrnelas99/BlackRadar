// Package controller tests NVD controller request handling.
package controller

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"blackradar/api/controller/dto"
	appcontext "blackradar/api/platform/requestcontext"
	baseservice "blackradar/api/service"
	matchservice "blackradar/api/service/match"
)

// TestNVDControllerLookupCVE verifies the successful CVE lookup response.
func TestNVDControllerLookupCVE(t *testing.T) {
	controller := NewNVDController(&fakeNVDLookupService{response: sampleCVELookupResponse()})
	ec, recorder := newNVDControllerContext(t, "CVE-2021-44228")

	controller.LookupCVE(ec)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	var response dto.CVELookupResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.CVEID != "CVE-2021-44228" {
		t.Fatalf("expected CVE ID, got %q", response.CVEID)
	}
}

// TestNVDControllerErrorMapping verifies safe API errors for lookup failures.
func TestNVDControllerErrorMapping(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{name: "invalid cve", err: matchservice.ErrInvalidCVEID, wantStatus: http.StatusBadRequest, wantCode: "VALIDATION_ERROR"},
		{name: "not found", err: matchservice.ErrCVENotFound, wantStatus: http.StatusNotFound, wantCode: "NOT_FOUND"},
		{name: "rate limited", err: matchservice.ErrNVDLookupRateLimited, wantStatus: http.StatusTooManyRequests, wantCode: "RATE_LIMITED"},
		{name: "upstream", err: matchservice.ErrMatchExternalService, wantStatus: http.StatusBadGateway, wantCode: "UPSTREAM_ERROR"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			controller := NewNVDController(&fakeNVDLookupService{err: tc.err})
			ec, recorder := newNVDControllerContext(t, "CVE-2021-44228")

			controller.LookupCVE(ec)

			if recorder.Code != tc.wantStatus {
				t.Fatalf("expected status %d, got %d", tc.wantStatus, recorder.Code)
			}
			var response dto.ErrorResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("failed to decode error response: %v", err)
			}
			if response.Code != tc.wantCode {
				t.Fatalf("expected code %q, got %q", tc.wantCode, response.Code)
			}
		})
	}
}

type fakeNVDLookupService struct {
	response dto.CVELookupResponse
	err      error
}

func (f *fakeNVDLookupService) LookupCVE(ec *appcontext.GinContext, cveID string) (dto.CVELookupResponse, error) {
	if f.err != nil {
		return dto.CVELookupResponse{}, f.err
	}
	return f.response, nil
}

var _ baseservice.NVDLookupService = (*fakeNVDLookupService)(nil)

func newNVDControllerContext(t *testing.T, cveID string) (*appcontext.GinContext, *httptest.ResponseRecorder) {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/nvd/cves/"+cveID, nil)
	ctx.Params = gin.Params{{Key: "cveId", Value: cveID}}
	ec := appcontext.NewGinContext(ctx, "txn-123", slog.New(slog.NewTextHandler(io.Discard, nil)))
	appcontext.SetGinContext(ctx, ec)
	return ec, recorder
}

func sampleCVELookupResponse() dto.CVELookupResponse {
	return dto.CVELookupResponse{
		CVEID:       "CVE-2021-44228",
		Title:       "CVE-2021-44228",
		Description: "Apache Log4j remote code execution.",
		Severity:    "CRITICAL",
		NVDURL:      "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
	}
}
