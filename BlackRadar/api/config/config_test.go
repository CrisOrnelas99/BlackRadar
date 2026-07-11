package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLoadUsesDefaults(t *testing.T) {
	clearConfigEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected defaults to load, got %v", err)
	}

	if cfg.Environment != EnvironmentDevelopment {
		t.Fatalf(
			"expected default environment %q, got %q",
			EnvironmentDevelopment,
			cfg.Environment,
		)
	}
	if cfg.Port != defaultPort {
		t.Fatalf("expected default port %q, got %q", defaultPort, cfg.Port)
	}
	if cfg.DatabaseURL != "postgres://secureops:secureops@localhost:5432/secureops" {
		t.Fatalf("unexpected default database URL: %q", cfg.DatabaseURL)
	}
	if cfg.JWTExpiration != defaultJWTExpiration {
		t.Fatalf(
			"expected default JWT expiration %s, got %s",
			defaultJWTExpiration,
			cfg.JWTExpiration,
		)
	}
	if cfg.JWTRefreshExpiration != defaultJWTRefreshExpiration {
		t.Fatalf(
			"expected default JWT refresh expiration %s, got %s",
			defaultJWTRefreshExpiration,
			cfg.JWTRefreshExpiration,
		)
	}
	if cfg.OpenAITimeout != defaultOpenAITimeout {
		t.Fatalf(
			"expected default OpenAI timeout %s, got %s",
			defaultOpenAITimeout,
			cfg.OpenAITimeout,
		)
	}
	if cfg.OpenAIModel != defaultOpenAIModel {
		t.Fatalf(
			"expected default OpenAI model %q, got %q",
			defaultOpenAIModel,
			cfg.OpenAIModel,
		)
	}
	if len(cfg.CorsAllowedOrigins) != 2 {
		t.Fatalf(
			"expected two default CORS origins, got %d",
			len(cfg.CorsAllowedOrigins),
		)
	}
	if cfg.BootstrapDevData {
		t.Fatal("expected bootstrap dev data to be disabled by default")
	}
	if cfg.BootstrapDevPassword != "" {
		t.Fatal("expected bootstrap password to be empty by default")
	}
}

func TestLoadUsesConfiguredValues(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("GO_ENV", " DEV ")
	t.Setenv("PORT", "9090")
	t.Setenv("DB_HOST", "db")
	t.Setenv("POSTGRES_PORT", "15432")
	t.Setenv("POSTGRES_DB", "app")
	t.Setenv("POSTGRES_USER", "user")
	t.Setenv("POSTGRES_PASSWORD", "p@ss word")
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("JWT_ISSUER", "issuer")
	t.Setenv("JWT_AUDIENCE", "audience")
	t.Setenv("JWT_EXPIRATION_MS", "60000")
	t.Setenv("JWT_REFRESH_EXPIRATION_MS", "120000")
	t.Setenv("NVD_API_KEY", "nvd-key")
	t.Setenv("OPENAI_API_KEY", "openai-key")
	t.Setenv("OPENAI_MODEL", "gpt-4.1")
	t.Setenv("OPENAI_TIMEOUT_SECONDS", "45")
	t.Setenv("BOOTSTRAP_DEV_DATA", "true")
	t.Setenv("BOOTSTRAP_DEV_PASSWORD", "LocalDevelopmentPassword123!")
	t.Setenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000, http://localhost:4200")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected configured values to load, got %v", err)
	}

	if cfg.Environment != EnvironmentDevelopment {
		t.Fatalf(
			"expected normalized environment %q, got %q",
			EnvironmentDevelopment,
			cfg.Environment,
		)
	}
	if cfg.Port != "9090" {
		t.Fatalf("expected configured port 9090, got %q", cfg.Port)
	}
	if cfg.DatabaseURL != "postgres://user:p%40ss%20word@db:15432/app" {
		t.Fatalf("unexpected configured database URL: %q", cfg.DatabaseURL)
	}
	if cfg.JWTExpiration != time.Minute {
		t.Fatalf("expected JWT expiration 1m, got %s", cfg.JWTExpiration)
	}
	if cfg.JWTRefreshExpiration != 2*time.Minute {
		t.Fatalf(
			"expected JWT refresh expiration 2m, got %s",
			cfg.JWTRefreshExpiration,
		)
	}
	if cfg.OpenAITimeout != 45*time.Second {
		t.Fatalf("expected OpenAI timeout 45s, got %s", cfg.OpenAITimeout)
	}
	if !cfg.BootstrapDevData {
		t.Fatal("expected bootstrap dev data to be enabled")
	}
	if cfg.BootstrapDevPassword != "LocalDevelopmentPassword123!" {
		t.Fatalf(
			"expected bootstrap password to load, got %q",
			cfg.BootstrapDevPassword,
		)
	}
}

func TestLoadUsesDatabaseURLOverride(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv(
		"DATABASE_URL",
		"postgres://override:pass@db.example.com:5432/overridedb",
	)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected database URL override to load, got %v", err)
	}

	if cfg.DatabaseURL != "postgres://override:pass@db.example.com:5432/overridedb" {
		t.Fatalf(
			"expected database URL override to be used, got %q",
			cfg.DatabaseURL,
		)
	}
}

func TestLoadRejectsUnknownEnvironment(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("GO_ENV", "sandbox")

	_, err := Load()
	if err == nil {
		t.Fatal("expected unknown environment to fail")
	}

	if !errors.Is(err, ErrInvalidEnvironment) {
		t.Fatalf("expected GO_ENV validation error, got %v", err)
	}
}

func TestLoadRejectsInvalidBoolean(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("BOOTSTRAP_DEV_DATA", "sometimes")

	_, err := Load()
	if err == nil {
		t.Fatal("expected invalid boolean to fail")
	}

	if !strings.Contains(err.Error(), "BOOTSTRAP_DEV_DATA") {
		t.Fatalf("expected boolean validation error, got %v", err)
	}
}

func TestLoadRejectsInvalidDuration(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("JWT_EXPIRATION_MS", "not-a-number")

	_, err := Load()
	if err == nil {
		t.Fatal("expected invalid duration to fail")
	}

	if !strings.Contains(err.Error(), "JWT_EXPIRATION_MS") {
		t.Fatalf("expected JWT duration validation error, got %v", err)
	}
}

func TestLoadRejectsBootstrapOutsideAllowedEnvironments(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("GO_ENV", "production")
	t.Setenv("BOOTSTRAP_DEV_DATA", "true")
	t.Setenv("BOOTSTRAP_DEV_PASSWORD", "LocalDevelopmentPassword123!")
	t.Setenv("JWT_SECRET", strings.Repeat("a", minimumProductionJWTSecretLength))
	t.Setenv("DATABASE_URL", "postgres://user:pass@db:5432/app")
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://example.com")

	_, err := Load()
	if err == nil {
		t.Fatal("expected production bootstrap data to fail")
	}

	if !errors.Is(err, ErrBootstrapNotAllowed) {
		t.Fatalf("expected bootstrap environment error, got %v", err)
	}
}

func TestLoadRequiresBootstrapPasswordWhenEnabled(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("BOOTSTRAP_DEV_DATA", "true")

	_, err := Load()
	if err == nil {
		t.Fatal("expected missing bootstrap password to fail")
	}

	if !errors.Is(err, ErrMissingBootstrapPassword) {
		t.Fatalf("expected bootstrap password error, got %v", err)
	}
}

func TestValidateRequiresJWTSecretInProduction(t *testing.T) {
	cfg := Config{
		Environment:          EnvironmentProduction,
		Port:                 defaultPort,
		DatabaseURL:          "postgres://user:pass@db:5432/app",
		JWTExpiration:        defaultJWTExpiration,
		JWTRefreshExpiration: defaultJWTRefreshExpiration,
		JWTIssuer:            defaultJWTIssuer,
		JWTAudience:          defaultJWTAudience,
		CorsAllowedOrigins:   []string{"https://example.com"},
		OpenAITimeout:        defaultOpenAITimeout,
	}

	if !errors.Is(cfg.Validate(), ErrMissingJWTSecret) {
		t.Fatalf("expected ErrMissingJWTSecret, got %v", cfg.Validate())
	}
}

func TestValidateRequiresMinimumProductionJWTSecretLength(t *testing.T) {
	cfg := Config{
		Environment:          EnvironmentProduction,
		Port:                 defaultPort,
		DatabaseURL:          "postgres://user:pass@db:5432/app",
		JWTSecret:            "short-secret",
		JWTExpiration:        defaultJWTExpiration,
		JWTRefreshExpiration: defaultJWTRefreshExpiration,
		JWTIssuer:            defaultJWTIssuer,
		JWTAudience:          defaultJWTAudience,
		CorsAllowedOrigins:   []string{"https://example.com"},
		OpenAITimeout:        defaultOpenAITimeout,
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected short production JWT secret to fail")
	}

	if !strings.Contains(err.Error(), "at least") {
		t.Fatalf("expected JWT secret length error, got %v", err)
	}
}

func TestValidateAllowsEmptyJWTSecretInDevelopment(t *testing.T) {
	cfg := Config{
		Environment:          EnvironmentDevelopment,
		Port:                 defaultPort,
		DatabaseURL:          "postgres://user:pass@db:5432/app",
		JWTExpiration:        defaultJWTExpiration,
		JWTRefreshExpiration: defaultJWTRefreshExpiration,
		JWTIssuer:            defaultJWTIssuer,
		JWTAudience:          defaultJWTAudience,
		CorsAllowedOrigins:   []string{"http://localhost:4200"},
		OpenAITimeout:        defaultOpenAITimeout,
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected development validation to succeed, got %v", err)
	}
}

func TestLoadUsesNoDefaultCORSOriginsInProduction(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("GO_ENV", "production")
	t.Setenv("JWT_SECRET", strings.Repeat("a", minimumProductionJWTSecretLength))
	t.Setenv("DATABASE_URL", "postgres://user:pass@db:5432/app")

	_, err := Load()
	if !errors.Is(err, ErrMissingCorsAllowedOrigins) {
		t.Fatalf("expected ErrMissingCorsAllowedOrigins, got %v", err)
	}
}

func TestLoadRejectsInvalidCORSOrigin(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("CORS_ALLOWED_ORIGINS", "http://localhost:4200/path")

	_, err := Load()
	if err == nil {
		t.Fatal("expected invalid CORS origin to fail")
	}

	if !strings.Contains(err.Error(), "CORS origin") {
		t.Fatalf("expected CORS validation error, got %v", err)
	}
}

func clearConfigEnv(t *testing.T) {
	t.Helper()

	keys := []string{
		"GO_ENV",
		"PORT",
		"DATABASE_URL",
		"DB_HOST",
		"POSTGRES_PORT",
		"POSTGRES_DB",
		"POSTGRES_USER",
		"POSTGRES_PASSWORD",
		"JWT_SECRET",
		"JWT_ISSUER",
		"JWT_AUDIENCE",
		"JWT_EXPIRATION_MS",
		"JWT_REFRESH_EXPIRATION_MS",
		"NVD_API_KEY",
		"OPENAI_API_KEY",
		"OPENAI_MODEL",
		"OPENAI_TIMEOUT_SECONDS",
		"BOOTSTRAP_DEV_DATA",
		"BOOTSTRAP_DEV_PASSWORD",
		"CORS_ALLOWED_ORIGINS",
		"CORS_ALLOWED_ORIGIN",
	}

	for _, key := range keys {
		t.Setenv(key, "")
	}
}
