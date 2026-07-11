package permissions

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	appcontext "blackradar/api/context"
	contextmiddleware "blackradar/api/middleware/context"
	"blackradar/api/model"
)

func TestRequireAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name           string
		role           any
		expectStatus   int
		expectContinue bool
	}{
		{name: "missing role", expectStatus: http.StatusForbidden},
		{name: "wrong type", role: 42, expectStatus: http.StatusForbidden},
		{name: "normal user", role: model.RoleUser, expectStatus: http.StatusForbidden},
		{name: "admin", role: model.RoleAdmin, expectStatus: http.StatusOK, expectContinue: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(contextmiddleware.RequestContext())
			if tt.role != nil {
				router.Use(func(ctx *gin.Context) {
					ec, err := appcontext.FromGinContext(ctx)
					if err != nil {
						t.Fatalf("expected request context, got %v", err)
					}
					if role, ok := tt.role.(string); ok {
						if err := ec.SetPrincipal(appcontext.Principal{
							UserID:         "00000000-0000-4000-8000-000000000042",
							Username:       "analyst",
							Role:           role,
							OrganizationID: "00000000-0000-4000-8000-000000000099",
						}); err != nil {
							t.Fatalf("failed to set principal: %v", err)
						}
					}
					ctx.Next()
				})
			}
			router.Use(RequireAdmin())

			handlerCalled := false
			router.GET("/admin", func(ctx *gin.Context) {
				handlerCalled = true
				ctx.Status(http.StatusOK)
			})

			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/admin", nil)
			router.ServeHTTP(recorder, request)

			if recorder.Code != tt.expectStatus {
				t.Fatalf("expected status %d, got %d", tt.expectStatus, recorder.Code)
			}
			if handlerCalled != tt.expectContinue {
				t.Fatalf("expected handler called=%v, got %v", tt.expectContinue, handlerCalled)
			}
		})
	}
}
