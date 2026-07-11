package cors

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCorsAllowsConfiguredOrigin(t *testing.T) {
	router := gin.New()
	router.Use(Cors([]string{"http://localhost:4200", "http://localhost:4000"}))
	router.OPTIONS("/auth/login", func(ctx *gin.Context) {
		ctx.Status(http.StatusOK)
	})

	recorder := performRequest(router, http.MethodOptions, "/auth/login", func(req *http.Request) {
		req.Header.Set("Origin", "http://localhost:4000")
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		req.Header.Set("Access-Control-Request-Headers", "content-type, authorization")
	})

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, recorder.Code)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:4000" {
		t.Fatalf("expected access-control-allow-origin to echo the request origin, got %q", got)
	}
}

func TestCorsRejectsUnlistedOrigin(t *testing.T) {
	router := gin.New()
	router.Use(Cors([]string{"http://localhost:4200"}))
	router.GET("/auth/login", func(ctx *gin.Context) {
		ctx.Status(http.StatusOK)
	})

	recorder := performRequest(router, http.MethodGet, "/auth/login", func(req *http.Request) {
		req.Header.Set("Origin", "http://malicious.example")
	})

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no access-control-allow-origin header, got %q", got)
	}
}

func performRequest(router http.Handler, method string, target string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, target, nil)
	if mutate != nil {
		mutate(request)
	}
	router.ServeHTTP(recorder, request)
	return recorder
}
