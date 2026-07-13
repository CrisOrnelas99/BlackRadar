package cors

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestCORSAllowsConfiguredPreflight(t *testing.T) {
	router := gin.New()
	middleware := mustNewCORS(t, Config{
		AllowedOrigins:   []string{"http://localhost:4200", "http://localhost:4000"},
		AllowedMethods:   []string{http.MethodPost, http.MethodGet},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		ExposedHeaders:   []string{"X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           time.Minute,
	})
	router.Use(middleware)
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
		t.Fatalf("expected access-control-allow-origin to echo request origin, got %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("expected credentials header true, got %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Expose-Headers"); got != "X-Request-Id" {
		t.Fatalf("expected exposed request ID header, got %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Max-Age"); got != "60" {
		t.Fatalf("expected max age 60, got %q", got)
	}
	assertVaryContains(t, recorder, "Origin")
	assertVaryContains(t, recorder, "Access-Control-Request-Method")
	assertVaryContains(t, recorder, "Access-Control-Request-Headers")
}

func TestCORSRejectsDisallowedPreflightOrigin(t *testing.T) {
	router := gin.New()
	router.Use(mustNewCORS(t, Config{AllowedOrigins: []string{"http://localhost:4200"}}))
	router.OPTIONS("/auth/login", func(ctx *gin.Context) {
		ctx.Status(http.StatusOK)
	})

	recorder := performRequest(router, http.MethodOptions, "/auth/login", func(req *http.Request) {
		req.Header.Set("Origin", "http://malicious.example")
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	})

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no access-control-allow-origin header, got %q", got)
	}
}

func TestCORSOmitsHeadersForDisallowedNormalRequest(t *testing.T) {
	router := gin.New()
	router.Use(mustNewCORS(t, Config{AllowedOrigins: []string{"http://localhost:4200"}}))
	router.GET("/auth/login", func(ctx *gin.Context) {
		ctx.Status(http.StatusOK)
	})

	recorder := performRequest(router, http.MethodGet, "/auth/login", func(req *http.Request) {
		req.Header.Set("Origin", "http://malicious.example")
	})

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no access-control-allow-origin header, got %q", got)
	}
}

func TestCORSRejectsDisallowedPreflightMethodAndHeaders(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		headers string
	}{
		{name: "method", method: http.MethodTrace, headers: "content-type"},
		{name: "headers", method: http.MethodPost, headers: "x-danger"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(mustNewCORS(t, Config{
				AllowedOrigins: []string{"http://localhost:4200"},
				AllowedMethods: []string{http.MethodPost},
				AllowedHeaders: []string{"Content-Type"},
			}))
			router.OPTIONS("/auth/login", func(ctx *gin.Context) {
				ctx.Status(http.StatusOK)
			})

			recorder := performRequest(router, http.MethodOptions, "/auth/login", func(req *http.Request) {
				req.Header.Set("Origin", "http://localhost:4200")
				req.Header.Set("Access-Control-Request-Method", tt.method)
				req.Header.Set("Access-Control-Request-Headers", tt.headers)
			})

			if recorder.Code != http.StatusForbidden {
				t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
			}
		})
	}
}

func TestCORSRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		expectErr error
	}{
		{name: "wildcard", cfg: Config{AllowedOrigins: []string{"*"}}, expectErr: ErrCORSWildcardOrigin},
		{name: "null", cfg: Config{AllowedOrigins: []string{"null"}}, expectErr: ErrCORSNullOrigin},
		{name: "path", cfg: Config{AllowedOrigins: []string{"https://example.com/app"}}, expectErr: ErrInvalidCORSOrigin},
		{name: "negative max age", cfg: Config{AllowedOrigins: []string{"https://example.com"}, MaxAge: -time.Second}, expectErr: ErrInvalidCORSMaxAge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware, err := New(tt.cfg)
			if err == nil {
				t.Fatalf("expected CORS config error, got middleware %#v", middleware)
			}
			if !errors.Is(err, tt.expectErr) {
				t.Fatalf("expected %v, got %v", tt.expectErr, err)
			}
		})
	}
}

func TestBuildOriginSetSkipsEmptyOrigins(t *testing.T) {
	origins, err := buildOriginSet([]string{"", "  ", "https://example.com"})
	if err != nil {
		t.Fatalf("expected origin set to build, got %v", err)
	}
	if _, exists := origins[""]; exists {
		t.Fatal("expected empty origin to be skipped")
	}
	if _, exists := origins["https://example.com"]; !exists {
		t.Fatal("expected configured origin to be present")
	}
}

func mustNewCORS(t *testing.T, cfg Config) gin.HandlerFunc {
	t.Helper()

	middleware, err := New(cfg)
	if err != nil {
		t.Fatalf("expected CORS middleware to build: %v", err)
	}
	return middleware
}

func assertVaryContains(t *testing.T, recorder *httptest.ResponseRecorder, expected string) {
	t.Helper()

	for _, value := range recorder.Header().Values("Vary") {
		for _, entry := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(entry), expected) {
				return
			}
		}
	}
	t.Fatalf("expected Vary to contain %q, got %#v", expected, recorder.Header().Values("Vary"))
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
