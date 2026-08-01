package runtime

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"blackradar/api/platform/config"
)

func TestBuildRouterRejectsMissingDatabase(t *testing.T) {
	cfg := testConfig()

	_, err := BuildRouter(cfg, nil, slog.Default())
	if err == nil {
		t.Fatal("expected missing database to fail")
	}

	if !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected database required error, got %v", err)
	}
}

func TestServerAddressUsesConfiguredPort(t *testing.T) {
	cfg := testConfig()
	cfg.Port = "9090"

	if actual := serverAddress(cfg); actual != ":9090" {
		t.Fatalf("expected :9090, got %q", actual)
	}
}

func TestNewHTTPServerUsesTimeoutAndHeaderLimits(t *testing.T) {
	cfg := testConfig()
	cfg.Port = "9090"

	server := newHTTPServer(http.NewServeMux(), cfg)

	if server.Addr != ":9090" {
		t.Fatalf("expected :9090, got %q", server.Addr)
	}
	if server.ReadHeaderTimeout != apiReadHeaderTimeout {
		t.Fatalf("expected read header timeout %s, got %s", apiReadHeaderTimeout, server.ReadHeaderTimeout)
	}
	if server.ReadTimeout != apiReadTimeout {
		t.Fatalf("expected read timeout %s, got %s", apiReadTimeout, server.ReadTimeout)
	}
	if server.WriteTimeout != apiWriteTimeout {
		t.Fatalf("expected write timeout %s, got %s", apiWriteTimeout, server.WriteTimeout)
	}
	if server.IdleTimeout != apiIdleTimeout {
		t.Fatalf("expected idle timeout %s, got %s", apiIdleTimeout, server.IdleTimeout)
	}
	if server.MaxHeaderBytes != apiMaxHeaderBytes {
		t.Fatalf("expected max header bytes %d, got %d", apiMaxHeaderBytes, server.MaxHeaderBytes)
	}
}

func TestBuildRouterConfiguresTrustedProxyResolution(t *testing.T) {
	tests := []struct {
		name           string
		trustedProxies []string
		remoteAddr     string
		wantClientIP   string
	}{
		{
			name:           "trusted proxy forwards client IP",
			trustedProxies: []string{"192.0.2.10"},
			remoteAddr:     "192.0.2.10:1234",
			wantClientIP:   "198.51.100.20",
		},
		{
			name:           "untrusted proxy cannot forward client IP",
			trustedProxies: []string{"192.0.2.11"},
			remoteAddr:     "192.0.2.10:1234",
			wantClientIP:   "192.0.2.10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := gin.New()
			cfg := testConfig()
			cfg.TrustedProxyCIDRs = tt.trustedProxies
			if err := configureTrustedProxies(engine, cfg); err != nil {
				t.Fatalf("set trusted proxies: %v", err)
			}
			engine.GET("/client-ip", func(ctx *gin.Context) {
				ctx.String(http.StatusOK, ctx.ClientIP())
			})

			request := httptest.NewRequest(http.MethodGet, "/client-ip", nil)
			request.RemoteAddr = tt.remoteAddr
			request.Header.Set("X-Forwarded-For", "198.51.100.20")
			recorder := httptest.NewRecorder()
			engine.ServeHTTP(recorder, request)

			if recorder.Body.String() != tt.wantClientIP {
				t.Fatalf("expected client IP %q, got %q", tt.wantClientIP, recorder.Body.String())
			}
		})
	}
}

func testConfig() config.Config {
	return config.Config{
		Environment:          config.EnvironmentTest,
		Port:                 "8080",
		JWTSecret:            "test-secret-with-at-least-thirty-two-bytes",
		JWTExpiration:        time.Hour,
		JWTRefreshExpiration: 24 * time.Hour,
		JWTIssuer:            "test",
		JWTAudience:          "test-api",
		CorsAllowedOrigins:   []string{"http://localhost:4200"},
		NVDAPIBaseURL:        "https://services.nvd.nist.gov/rest/json/cves/2.0",
		NVDCPEAPIBaseURL:     "https://services.nvd.nist.gov/rest/json/cpes/2.0",
		OpenAIAPIEndpoint:    "https://api.openai.com/v1/responses",
		OpenAIModel:          "gpt-4.1-mini",
		OpenAITimeout:        20 * time.Second,
	}
}
