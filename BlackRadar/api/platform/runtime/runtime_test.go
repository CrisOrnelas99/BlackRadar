package runtime

import (
	"errors"
	"log/slog"
	"testing"
	"time"

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
