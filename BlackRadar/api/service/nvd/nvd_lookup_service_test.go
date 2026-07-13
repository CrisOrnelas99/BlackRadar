// Package service verifies NVD lookup service behavior.
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

	appcontext "blackradar/api/context"
	"blackradar/api/controller/dto"
	nvdcveclient "blackradar/api/external/nvd_cve"
	"blackradar/api/model"
	baseservice "blackradar/api/service"
)

// TestNVDLookupService verifies validation and successful lookup behavior.
func TestNVDLookupService(t *testing.T) {
	client := &fakeCVELookupClient{response: sampleCVELookupResponse()}
	svc := NewNVDLookupService(client)
	ec := newNVDServiceContext(t, "00000000-0000-4000-8000-000000000042")

	response, err := svc.LookupCVE(ec, " cve-2021-44228 ")
	if err != nil {
		t.Fatalf("expected lookup to succeed, got %v", err)
	}
	if client.cveID != "CVE-2021-44228" {
		t.Fatalf("expected normalized CVE ID, got %q", client.cveID)
	}
	if response.CVEID != "CVE-2021-44228" {
		t.Fatalf("expected response CVE ID, got %q", response.CVEID)
	}
}

// TestNVDLookupServiceValidation verifies invalid CVE IDs fail before NVD is called.
func TestNVDLookupServiceValidation(t *testing.T) {
	client := &fakeCVELookupClient{response: sampleCVELookupResponse()}
	svc := NewNVDLookupService(client)
	ec := newNVDServiceContext(t, "00000000-0000-4000-8000-000000000042")

	_, err := svc.LookupCVE(ec, "https://evil.example/cve")
	if !errors.Is(err, baseservice.ErrInvalidRequestData) {
		t.Fatalf("expected invalid request data, got %v", err)
	}
	if client.called {
		t.Fatal("expected invalid CVE ID to fail before client call")
	}
}

// TestNVDLookupServiceErrorMapping verifies NVD client errors become service errors.
func TestNVDLookupServiceErrorMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error
	}{
		{name: "not found", err: nvdcveclient.ErrCVEIDNotFound, want: baseservice.ErrNotFound},
		{name: "rate limited", err: nvdcveclient.ErrNVDRateLimited, want: baseservice.ErrRateLimited},
		{name: "invalid response", err: nvdcveclient.ErrInvalidNVDResponse, want: baseservice.ErrExternalService},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewNVDLookupService(&fakeCVELookupClient{err: tc.err})
			ec := newNVDServiceContext(t, "00000000-0000-4000-8000-000000000042")

			_, err := svc.LookupCVE(ec, "CVE-2021-44228")
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

type fakeCVELookupClient struct {
	response dto.CVELookupResponse
	err      error
	cveID    string
	called   bool
}

func (f *fakeCVELookupClient) LookupCVE(ctx context.Context, cveID string) (dto.CVELookupResponse, error) {
	f.called = true
	f.cveID = cveID
	return f.response, f.err
}

func newNVDServiceContext(t *testing.T, userID string) *appcontext.GinContext {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ec := appcontext.NewGinContext(ctx, "txn-123", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := ec.SetPrincipal(appcontext.Principal{
		UserID:         userID,
		Username:       "analyst",
		Role:           model.RoleAdmin,
		OrganizationID: "00000000-0000-4000-8000-000000000099",
	}); err != nil {
		t.Fatalf("failed to set test principal: %v", err)
	}
	appcontext.SetGinContext(ctx, ec)
	return ec
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
