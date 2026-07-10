package config

import (
	"errors"
	"testing"
	"time"
)

// TestLoadUsesDefaults verifies Load fills default values when environment variables are absent.
func TestLoadUsesDefaults(t *testing.T) {
	clearConfigEnv(t)

	cfg := Load()

	if cfg.Port != "8080" {
		t.Fatalf("expected default port 8080, got %q", cfg.Port)
	}
	if cfg.DatabaseURL != "postgres://secureops:secureops@localhost:5432/secureops" {
		t.Fatalf("unexpected default database URL: %q", cfg.DatabaseURL)
	}
	if cfg.JWTSecret != "" {
		t.Fatalf("expected default JWT secret to be empty, got %q", cfg.JWTSecret)
	}
	if cfg.JWTExpiration != time.Hour {
		t.Fatalf("expected default JWT expiration %s, got %s", time.Hour, cfg.JWTExpiration)
	}
	if cfg.JWTIssuer != "secureops" {
		t.Fatalf("expected default JWT issuer secureops, got %q", cfg.JWTIssuer)
	}
	if cfg.JWTAudience != "secureops-api" {
		t.Fatalf("expected default JWT audience secureops-api, got %q", cfg.JWTAudience)
	}
	if len(cfg.CorsAllowedOrigins) != 2 {
		t.Fatalf("expected two default CORS allowed origins, got %d", len(cfg.CorsAllowedOrigins))
	}
	if cfg.CorsAllowedOrigins[0] != "http://localhost:4200" || cfg.CorsAllowedOrigins[1] != "http://localhost:4000" {
		t.Fatalf("unexpected default CORS allowed origins: %#v", cfg.CorsAllowedOrigins)
	}
	if cfg.NVDAPIBaseURL != nvdCVEAPIBaseURL {
		t.Fatalf("expected default NVD API base URL, got %q", cfg.NVDAPIBaseURL)
	}
	if cfg.NVDCPEAPIBaseURL != nvdCPEAPIBaseURL {
		t.Fatalf("expected default NVD CPE API base URL, got %q", cfg.NVDCPEAPIBaseURL)
	}
	if cfg.NVDAPIKey != "" {
		t.Fatal("expected default NVD API key to be empty")
	}
	if cfg.OpenAIAPIEndpoint != openAIResponsesEndpoint {
		t.Fatalf("expected default OpenAI API endpoint, got %q", cfg.OpenAIAPIEndpoint)
	}
	if cfg.OpenAIAPIKey != "" {
		t.Fatal("expected default OpenAI API key to be empty")
	}
	if cfg.OpenAIModel != "gpt-4.1-mini" {
		t.Fatalf("expected default OpenAI model gpt-4.1-mini, got %q", cfg.OpenAIModel)
	}
	if cfg.OpenAITimeout != 20*time.Second {
		t.Fatalf("expected default OpenAI timeout 20s, got %s", cfg.OpenAITimeout)
	}
	if cfg.BootstrapDevData {
		t.Fatal("expected bootstrap dev data to be disabled by default")
	}
}

// TestLoadUsesEnvironment verifies Load reads values from environment variables.
func TestLoadUsesEnvironment(t *testing.T) {
	t.Setenv("PORT", "9090")
	t.Setenv("DB_HOST", "db")
	t.Setenv("POSTGRES_PORT", "15432")
	t.Setenv("POSTGRES_DB", "app")
	t.Setenv("POSTGRES_USER", "user")
	t.Setenv("POSTGRES_PASSWORD", "pass")
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("JWT_ISSUER", "issuer")
	t.Setenv("JWT_AUDIENCE", "audience")
	t.Setenv("JWT_EXPIRATION_MS", "60000")
	t.Setenv("NVD_API_KEY", "nvd-key")
	t.Setenv("OPENAI_API_KEY", "openai-key")
	t.Setenv("OPENAI_MODEL", "gpt-4.1")
	t.Setenv("OPENAI_TIMEOUT_SECONDS", "45")
	t.Setenv("BOOTSTRAP_DEV_DATA", "true")
	t.Setenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000, http://localhost:4200")

	cfg := Load()

	if cfg.Port != "9090" {
		t.Fatalf("expected configured port 9090, got %q", cfg.Port)
	}
	if cfg.DatabaseURL != "postgres://user:pass@db:15432/app" {
		t.Fatalf("unexpected configured database URL: %q", cfg.DatabaseURL)
	}
	if cfg.JWTSecret != "test-secret" {
		t.Fatalf("expected configured JWT secret, got %q", cfg.JWTSecret)
	}
	if cfg.JWTExpiration != time.Minute {
		t.Fatalf("expected configured JWT expiration %s, got %s", time.Minute, cfg.JWTExpiration)
	}
	if cfg.JWTIssuer != "issuer" {
		t.Fatalf("expected configured JWT issuer issuer, got %q", cfg.JWTIssuer)
	}
	if cfg.JWTAudience != "audience" {
		t.Fatalf("expected configured JWT audience audience, got %q", cfg.JWTAudience)
	}
	if cfg.NVDAPIKey != "nvd-key" {
		t.Fatalf("expected configured NVD API key, got %q", cfg.NVDAPIKey)
	}
	if cfg.OpenAIAPIKey != "openai-key" {
		t.Fatalf("expected configured OpenAI API key, got %q", cfg.OpenAIAPIKey)
	}
	if cfg.OpenAIModel != "gpt-4.1" {
		t.Fatalf("expected configured OpenAI model gpt-4.1, got %q", cfg.OpenAIModel)
	}
	if cfg.OpenAITimeout != 45*time.Second {
		t.Fatalf("expected configured OpenAI timeout 45s, got %s", cfg.OpenAITimeout)
	}
	if !cfg.BootstrapDevData {
		t.Fatal("expected bootstrap dev data to be enabled")
	}
	if len(cfg.CorsAllowedOrigins) != 2 || cfg.CorsAllowedOrigins[0] != "http://localhost:3000" || cfg.CorsAllowedOrigins[1] != "http://localhost:4200" {
		t.Fatalf("unexpected configured CORS allowed origins: %#v", cfg.CorsAllowedOrigins)
	}
}

// TestLoadFallsBackForInvalidJWTExpiration checks invalid JWT_EXPIRATION_MS falls back to the default.
func TestLoadFallsBackForInvalidJWTExpiration(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("JWT_EXPIRATION_MS", "not-a-number")

	cfg := Load()

	if cfg.JWTExpiration != time.Hour {
		t.Fatalf("expected invalid JWT expiration to fall back to %s, got %s", time.Hour, cfg.JWTExpiration)
	}
}

// TestLoadFallsBackForNonPositiveJWTExpiration checks non-positive expiration values use the default.
func TestLoadFallsBackForNonPositiveJWTExpiration(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("JWT_EXPIRATION_MS", "0")

	cfg := Load()

	if cfg.JWTExpiration != time.Hour {
		t.Fatalf("expected non-positive JWT expiration to fall back to %s, got %s", time.Hour, cfg.JWTExpiration)
	}
}

// TestLoadUsesDatabaseURLOverride verifies DATABASE_URL overrides the assembled database connection string.
func TestLoadUsesDatabaseURLOverride(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("DATABASE_URL", "postgres://override:pass@db.example.com:5432/overridedb")

	cfg := Load()

	if cfg.DatabaseURL != "postgres://override:pass@db.example.com:5432/overridedb" {
		t.Fatalf("expected database URL override to be used, got %q", cfg.DatabaseURL)
	}
}

// TestValidateRequiresJwtSecretInProduction ensures Validate fails when JWT_SECRET is missing in production.
func TestValidateRequiresJwtSecretInProduction(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("GO_ENV", "production")

	cfg := Load()
	if !errors.Is(cfg.Validate(), ErrMissingJWTSecret) {
		t.Fatalf("expected ErrMissingJWTSecret, got %v", cfg.Validate())
	}
}

// TestValidateAllowsEmptyJwtSecretInDevelopment ensures Validate succeeds in development with no JWT_SECRET.
func TestValidateAllowsEmptyJwtSecretInDevelopment(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("GO_ENV", "development")

	cfg := Load()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected Validate to succeed in development, got %v", err)
	}
}

// TestValidateRequiresCorsAllowedOriginsInProduction ensures production requires CORS allowlist values.
func TestValidateRequiresCorsAllowedOriginsInProduction(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("GO_ENV", "production")
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("DATABASE_URL", "postgres://user:pass@db:5432/app")
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://example.com")

	cfg := Load()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected Validate to succeed when CORS_ALLOWED_ORIGINS is present, got %v", err)
	}
}

// TestLoadUsesCustomCorsAllowedOrigins verifies Load sets CorsAllowedOrigins from the environment.
func TestLoadUsesCustomCorsAllowedOrigins(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://example.com, https://admin.example.com")

	cfg := Load()

	if len(cfg.CorsAllowedOrigins) != 2 {
		t.Fatalf("expected 2 CORS allowed origins, got %d", len(cfg.CorsAllowedOrigins))
	}
	if cfg.CorsAllowedOrigins[0] != "https://example.com" || cfg.CorsAllowedOrigins[1] != "https://admin.example.com" {
		t.Fatalf("unexpected CORS allowed origins: %#v", cfg.CorsAllowedOrigins)
	}
}

// clearConfigEnv clears config-related environment variables for a clean test setup.
func clearConfigEnv(t *testing.T) {
	t.Helper()

	keys := []string{
		"PORT",
		"DB_HOST",
		"POSTGRES_PORT",
		"POSTGRES_DB",
		"POSTGRES_USER",
		"POSTGRES_PASSWORD",
		"JWT_SECRET",
		"JWT_ISSUER",
		"JWT_AUDIENCE",
		"JWT_EXPIRATION_MS",
		"NVD_API_KEY",
		"OPENAI_API_KEY",
		"OPENAI_MODEL",
		"OPENAI_TIMEOUT_SECONDS",
		"BOOTSTRAP_DEV_DATA",
		"CORS_ALLOWED_ORIGINS",
		"CORS_ALLOWED_ORIGIN",
	}

	for _, key := range keys {
		t.Setenv(key, "")
	}
}
