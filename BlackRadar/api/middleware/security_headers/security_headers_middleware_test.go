package securityheaders

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSecurityHeadersAddsAPIHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := newSecurityHeadersRouter(Config{
		EnableHSTS:         false,
		HSTSMaxAge:         31536000,
		HSTSIncludeDomains: true,
	})

	recorder := performRequest(router, httptest.NewRequest(http.MethodGet, "/resource", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	expectedHeaders := map[string]string{
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Permissions-Policy":      "geolocation=(), microphone=(), camera=()",
	}

	for header, expected := range expectedHeaders {
		if actual := recorder.Header().Get(header); actual != expected {
			t.Errorf("expected %s header %q, got %q", header, expected, actual)
		}
	}

	if actual := recorder.Header().Get("Strict-Transport-Security"); actual != "" {
		t.Errorf("expected HSTS to be omitted, got %q", actual)
	}
}

func TestSecurityHeadersAddsHSTSForHTTPS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := newSecurityHeadersRouter(Config{
		EnableHSTS:         true,
		HSTSMaxAge:         31536000,
		HSTSIncludeDomains: true,
	})

	request := httptest.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
	request.TLS = &tls.ConnectionState{}
	recorder := performRequest(router, request)

	const expected = "max-age=31536000; includeSubDomains"
	if actual := recorder.Header().Get("Strict-Transport-Security"); actual != expected {
		t.Fatalf("expected HSTS header %q, got %q", expected, actual)
	}
}

func TestSecurityHeadersOmitsHSTSForHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := newSecurityHeadersRouter(Config{
		EnableHSTS:         true,
		HSTSMaxAge:         31536000,
		HSTSIncludeDomains: true,
	})

	request := httptest.NewRequest(http.MethodGet, "http://api.example.com/resource", nil)
	recorder := performRequest(router, request)

	if actual := recorder.Header().Get("Strict-Transport-Security"); actual != "" {
		t.Fatalf("expected HSTS to be omitted for HTTP, got %q", actual)
	}
}

func TestSecurityHeadersUsesTrustedForwardedHTTPS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := newSecurityHeadersRouter(Config{
		EnableHSTS:          true,
		HSTSMaxAge:          31536000,
		HSTSIncludeDomains:  true,
		TrustForwardedProto: true,
	})

	request := httptest.NewRequest(http.MethodGet, "http://api.example.com/resource", nil)
	request.Header.Set("X-Forwarded-Proto", "https")
	recorder := performRequest(router, request)

	const expected = "max-age=31536000; includeSubDomains"
	if actual := recorder.Header().Get("Strict-Transport-Security"); actual != expected {
		t.Fatalf("expected HSTS header %q, got %q", expected, actual)
	}
}

func TestSecurityHeadersIgnoresUntrustedForwardedHTTPS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := newSecurityHeadersRouter(Config{
		EnableHSTS:          true,
		HSTSMaxAge:          31536000,
		HSTSIncludeDomains:  true,
		TrustForwardedProto: false,
	})

	request := httptest.NewRequest(http.MethodGet, "http://api.example.com/resource", nil)
	request.Header.Set("X-Forwarded-Proto", "https")
	recorder := performRequest(router, request)

	if actual := recorder.Header().Get("Strict-Transport-Security"); actual != "" {
		t.Fatalf("expected HSTS to ignore untrusted forwarded proto, got %q", actual)
	}
}

func newSecurityHeadersRouter(cfg Config) *gin.Engine {
	router := gin.New()
	router.Use(SecurityHeaders(cfg))
	router.GET("/resource", func(ctx *gin.Context) {
		ctx.Status(http.StatusOK)
	})
	return router
}

func performRequest(router http.Handler, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}
