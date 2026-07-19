package permissions

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	contextmiddleware "blackradar/api/middleware/context"
	"blackradar/api/model"
	requestcontext "blackradar/api/platform/requestcontext"
)

func TestRequireAdminRejectsMissingRequestContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequireAdmin())
	router.GET("/admin", func(ctx *gin.Context) {
		t.Fatal("handler should not run")
	})

	recorder := performRequest(router, http.MethodGet, "/admin")

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, recorder.Code)
	}
	if recorder.Body.String() != `{"error":"internal server error"}` {
		t.Fatalf("unexpected response body: %q", recorder.Body.String())
	}
}

func TestRequireAdminRejectsMissingPrincipal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(contextmiddleware.RequestContext(nil))
	router.Use(RequireAdmin())
	router.GET("/admin", func(ctx *gin.Context) {
		t.Fatal("handler should not run")
	})

	recorder := performRequest(router, http.MethodGet, "/admin")

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, recorder.Code)
	}
	if recorder.Body.String() != `{"error":"Unauthorized"}` {
		t.Fatalf("unexpected response body: %q", recorder.Body.String())
	}
	if recorder.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("expected WWW-Authenticate Bearer header")
	}
}

func TestRequireAdminRejectsNonAdminPrincipal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(contextmiddleware.RequestContext(nil))
	router.Use(setPrincipal(model.RoleUser))
	router.Use(RequireAdmin())
	router.GET("/admin", func(ctx *gin.Context) {
		t.Fatal("handler should not run")
	})

	recorder := performRequest(router, http.MethodGet, "/admin")

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}
	if recorder.Body.String() != `{"error":"forbidden"}` {
		t.Fatalf("unexpected response body: %q", recorder.Body.String())
	}
}

func TestRequireAdminAllowsAdminPrincipal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(contextmiddleware.RequestContext(nil))
	router.Use(setPrincipal(model.RoleAdmin))
	router.Use(RequireAdmin())

	handlerCalled := false
	router.GET("/admin", func(ctx *gin.Context) {
		handlerCalled = true
		ctx.Status(http.StatusOK)
	})

	recorder := performRequest(router, http.MethodGet, "/admin")

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if !handlerCalled {
		t.Fatal("expected handler to be called")
	}
}

func setPrincipal(role string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ec, err := requestcontext.FromGinContext(ctx)
		if err != nil {
			panic(err)
		}
		if err := ec.SetPrincipal(requestcontext.Principal{
			UserID:   "00000000-0000-4000-8000-000000000042",
			Username: "analyst",
			Role:     role,
		}); err != nil {
			panic(err)
		}
		ctx.Next()
	}
}

func performRequest(router http.Handler, method string, target string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, target, nil)
	router.ServeHTTP(recorder, request)
	return recorder
}
