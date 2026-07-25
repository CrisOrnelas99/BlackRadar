// Package shared_test verifies shared controller helpers.
package shared_test

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	shared "blackradar/api/controller/shared"
	appcontext "blackradar/api/platform/requestcontext"
)

type bindJSONRequest struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Owner       string `json:"owner"`
	Criticality string `json:"criticality"`
}

func TestControllerHelper(t *testing.T) {
	t.Run("parse id", func(t *testing.T) {
		id, err := shared.ParseID("00000000-0000-4000-8000-000000000042")
		if err != nil {
			t.Fatalf("expected id to parse, got %v", err)
		}
		if id != "00000000-0000-4000-8000-000000000042" {
			t.Fatalf("expected UUID, got %s", id)
		}
	})

	t.Run("parse pair", func(t *testing.T) {
		ec, _ := newControllerContext(t, http.MethodPost, "/assets/00000000-0000-4000-8000-000000000001/vulnerabilities/00000000-0000-4000-8000-000000000002", "")
		ec.Params = gin.Params{
			{Key: "id", Value: "00000000-0000-4000-8000-000000000001"},
			{Key: "vulnerabilityId", Value: "00000000-0000-4000-8000-000000000002"},
		}

		assetID, vulnerabilityID, ok := shared.ParsePair(ec)
		if !ok {
			t.Fatal("expected identifier pair to parse")
		}
		if assetID != "00000000-0000-4000-8000-000000000001" {
			t.Fatalf("expected asset UUID, got %s", assetID)
		}
		if vulnerabilityID != "00000000-0000-4000-8000-000000000002" {
			t.Fatalf("expected vulnerability UUID, got %s", vulnerabilityID)
		}
	})

	t.Run("bind json", func(t *testing.T) {
		ec, recorder := newControllerContext(t, http.MethodPost, "/assets", `{"name":"Asset 1","type":"Server","owner":"IT","criticality":"High"}`)
		ec.Request.Header.Set("Content-Type", "application/json")

		var request bindJSONRequest
		if handled := shared.BindJSON(ec, &request); handled {
			t.Fatal("expected request to bind")
		}
		if request.Name != "Asset 1" {
			t.Fatalf("expected Asset 1, got %q", request.Name)
		}
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected no error response, got %d", recorder.Code)
		}
	})

	t.Run("bind json rejects malformed content type", func(t *testing.T) {
		ec, recorder := newControllerContext(t, http.MethodPost, "/assets", `{"name":"Asset 1"}`)
		ec.Request.Header.Set("Content-Type", "application/jsonfoo")

		var request bindJSONRequest
		if handled := shared.BindJSON(ec, &request); !handled {
			t.Fatal("expected malformed content type to be rejected")
		}
		if recorder.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("expected status %d, got %d", http.StatusUnsupportedMediaType, recorder.Code)
		}
	})

	t.Run("handle error", func(t *testing.T) {
		ec, recorder := newControllerContext(t, http.MethodGet, "/resource", "")
		if !shared.HandleError(ec, http.StatusBadRequest, errors.New("boom"), "Invalid request body") {
			t.Fatal("expected error to be handled")
		}

		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
		}

		var response shared.ErrorResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("failed to decode error response: %v", err)
		}
		if response.Code != "VALIDATION_ERROR" {
			t.Fatalf("expected validation error code, got %q", response.Code)
		}
	})
}

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
	ec := appcontext.NewGinContext(ctx, "txn-123", slog.New(slog.NewTextHandler(io.Discard, nil)))
	appcontext.SetGinContext(ctx, ec)
	return ec, recorder
}
