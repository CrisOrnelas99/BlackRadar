// Package controller tests dashboard AI HTTP response mapping.
package controller

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	contextmiddleware "blackradar/api/middleware/context"
	"blackradar/api/middleware/permissions"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
	aiservice "blackradar/api/service/ai"
	textgenerationservice "blackradar/api/service/text_generation"
)

func TestGenerateDashboardSummaryReturnsValidatedServiceResult(t *testing.T) {
	controller := NewAIController(fakeAIService{})
	ec, recorder := newDashboardControllerContext(t)

	controller.GenerateDashboardSummary(ec)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	var response AIDashboardSummaryResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Headline != "Attention needed" || len(response.PriorityFindings) != 1 {
		t.Fatalf("unexpected dashboard response: %+v", response)
	}
}

func TestRegisterDashboardRoutesRejectsUnauthenticatedRequests(t *testing.T) {
	engine := newDashboardRouteTestEngine(t, "")
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/dashboard/ai-summary", nil)

	engine.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, recorder.Code)
	}
}

func TestRegisterDashboardRoutesRejectsUsersWithoutDashboardPermission(t *testing.T) {
	engine := newDashboardRouteTestEngine(t, "unknown")
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/dashboard/ai-summary", nil)

	engine.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}
}

type fakeAIService struct{}

func (fakeAIService) TestProvider(context.Context) (textgenerationservice.TextGenerationResponse, error) {
	return textgenerationservice.TextGenerationResponse{}, nil
}

func (fakeAIService) GenerateDashboardSummary(*appcontext.GinContext) (aiservice.DashboardSummary, error) {
	return aiservice.DashboardSummary{
		Headline:          "Attention needed",
		OverallAssessment: "high",
		Summary:           "One asset needs review.",
		PriorityFindings: []aiservice.DashboardFinding{{
			Priority: 1, AssetID: "asset-1", AssetName: "Production DB",
			VulnerabilityID: "vulnerability-1", CVEID: "CVE-2024-0001",
			Explanation: "The asset is affected.", RiskReason: "The vulnerability is high severity.",
			RecommendedNextStep: "Apply the vendor patch.",
		}},
	}, nil
}

func newDashboardControllerContext(t *testing.T) (*appcontext.GinContext, *httptest.ResponseRecorder) {
	t.Helper()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/dashboard/ai-summary", nil)
	ec := appcontext.NewGinContext(ctx, "txn-123", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := ec.SetPrincipal(appcontext.Principal{UserID: "user-1", Username: "user", Role: "user"}); err != nil {
		t.Fatalf("set principal: %v", err)
	}
	return ec, recorder
}

func newDashboardRouteTestEngine(t *testing.T, role string) *gin.Engine {
	t.Helper()
	engine := gin.New()
	engine.Use(contextmiddleware.RequestContext(nil))
	if role != "" {
		engine.Use(func(ctx *gin.Context) {
			ec, err := appcontext.FromGinContext(ctx)
			if err != nil {
				t.Fatalf("get request context: %v", err)
			}
			if err := ec.SetPrincipal(appcontext.Principal{UserID: "user-1", Username: "user", Role: role}); err != nil {
				t.Fatalf("set principal: %v", err)
			}
			ctx.Next()
		})
	}
	dashboard := engine.Group("/api")
	dashboard.Use(permissions.RequirePermission(model.PermissionViewDashboard))
	RegisterDashboardRoutes(dashboard, NewAIController(fakeAIService{}))
	return engine
}
