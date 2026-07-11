// Package config loads and validates application settings from environment
// variables.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	EnvironmentLocal       = "local"
	EnvironmentDevelopment = "development"
	EnvironmentTest        = "test"
	EnvironmentStaging     = "staging"
	EnvironmentProduction  = "production"

	nvdCVEAPIBaseURL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdCPEAPIBaseURL        = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
	openAIResponsesEndpoint = "https://api.openai.com/v1/responses"

	defaultPort                  = "8080"
	defaultJWTIssuer             = "secureops"
	defaultJWTAudience           = "secureops-api"
	defaultJWTExpiration         = time.Hour
	defaultJWTRefreshExpiration  = 7 * 24 * time.Hour
	defaultOpenAITimeout         = 20 * time.Second
	defaultOpenAIModel           = "gpt-4.1-mini"
	defaultDevCorsAllowedOrigins = "http://localhost:4200,http://localhost:4000"

	minimumProductionJWTSecretLength = 32
)

// Config holds application settings loaded from environment variables.
type Config struct {
	Environment string
	Port        string
	DatabaseURL string

	JWTSecret            string
	JWTExpiration        time.Duration
	JWTRefreshExpiration time.Duration
	JWTIssuer            string
	JWTAudience          string

	CorsAllowedOrigins []string

	NVDAPIBaseURL    string
	NVDCPEAPIBaseURL string
	NVDAPIKey        string

	OpenAIAPIEndpoint string
	OpenAIAPIKey      string
	OpenAIModel       string
	OpenAITimeout     time.Duration

	BootstrapDevData     bool
	BootstrapDevPassword string
}

// Load reads configuration from environment variables.
//
// Invalid explicitly configured values return an error instead of silently
// falling back to defaults.
func Load() (Config, error) {
	environment, err := normalizeEnvironment(
		env("GO_ENV", EnvironmentDevelopment),
	)
	if err != nil {
		return Config{}, err
	}

	port := env("PORT", defaultPort)
	if err := validatePort("PORT", port); err != nil {
		return Config{}, err
	}

	databaseURL, err := loadDatabaseURL(environment)
	if err != nil {
		return Config{}, err
	}

	jwtExpiration, err := durationFromMilliseconds(
		"JWT_EXPIRATION_MS",
		defaultJWTExpiration,
	)
	if err != nil {
		return Config{}, err
	}

	jwtRefreshExpiration, err := durationFromMilliseconds(
		"JWT_REFRESH_EXPIRATION_MS",
		defaultJWTRefreshExpiration,
	)
	if err != nil {
		return Config{}, err
	}

	openAITimeout, err := durationFromSeconds(
		"OPENAI_TIMEOUT_SECONDS",
		defaultOpenAITimeout,
	)
	if err != nil {
		return Config{}, err
	}

	bootstrapDevData, err := boolFromEnvironment(
		"BOOTSTRAP_DEV_DATA",
		false,
	)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		Environment: environment,
		Port:        port,
		DatabaseURL: databaseURL,

		JWTSecret:            env("JWT_SECRET", ""),
		JWTExpiration:        jwtExpiration,
		JWTRefreshExpiration: jwtRefreshExpiration,
		JWTIssuer:            env("JWT_ISSUER", defaultJWTIssuer),
		JWTAudience:          env("JWT_AUDIENCE", defaultJWTAudience),

		CorsAllowedOrigins: loadCorsAllowedOrigins(environment),

		NVDAPIBaseURL:    nvdCVEAPIBaseURL,
		NVDCPEAPIBaseURL: nvdCPEAPIBaseURL,
		NVDAPIKey:        env("NVD_API_KEY", ""),

		OpenAIAPIEndpoint: openAIResponsesEndpoint,
		OpenAIAPIKey:      env("OPENAI_API_KEY", ""),
		OpenAIModel:       env("OPENAI_MODEL", defaultOpenAIModel),
		OpenAITimeout:     openAITimeout,

		BootstrapDevData:     bootstrapDevData,
		BootstrapDevPassword: env("BOOTSTRAP_DEV_PASSWORD", ""),
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// Validate verifies configuration requirements and security restrictions.
func (cfg Config) Validate() error {
	if _, err := normalizeEnvironment(cfg.Environment); err != nil {
		return err
	}

	if strings.TrimSpace(cfg.Port) == "" {
		return fmt.Errorf("PORT is required")
	}

	if err := validatePort("PORT", cfg.Port); err != nil {
		return err
	}

	if cfg.JWTExpiration <= 0 {
		return fmt.Errorf("JWT_EXPIRATION_MS must be greater than zero")
	}

	if cfg.JWTRefreshExpiration <= 0 {
		return fmt.Errorf(
			"JWT_REFRESH_EXPIRATION_MS must be greater than zero",
		)
	}

	if cfg.OpenAITimeout <= 0 {
		return fmt.Errorf("OPENAI_TIMEOUT_SECONDS must be greater than zero")
	}

	if strings.TrimSpace(cfg.JWTIssuer) == "" {
		return fmt.Errorf("JWT_ISSUER is required")
	}

	if strings.TrimSpace(cfg.JWTAudience) == "" {
		return fmt.Errorf("JWT_AUDIENCE is required")
	}

	if cfg.BootstrapDevData {
		if !cfg.AllowsBootstrapData() {
			return fmt.Errorf(
				"%w: %q",
				ErrBootstrapNotAllowed,
				cfg.Environment,
			)
		}

		if strings.TrimSpace(cfg.BootstrapDevPassword) == "" {
			return fmt.Errorf(
				"%w",
				ErrMissingBootstrapPassword,
			)
		}
	}

	if cfg.IsProduction() {
		if strings.TrimSpace(cfg.JWTSecret) == "" {
			return ErrMissingJWTSecret
		}

		if len(cfg.JWTSecret) < minimumProductionJWTSecretLength {
			return fmt.Errorf(
				"JWT_SECRET must contain at least %d characters in production",
				minimumProductionJWTSecretLength,
			)
		}

		if strings.TrimSpace(cfg.DatabaseURL) == "" {
			return ErrMissingDatabaseURL
		}

		if len(cfg.CorsAllowedOrigins) == 0 {
			return ErrMissingCorsAllowedOrigins
		}
	}

	for _, origin := range cfg.CorsAllowedOrigins {
		if err := validateCORSOrigin(origin); err != nil {
			return err
		}
	}

	return nil
}

// IsProduction reports whether this configuration targets production.
func (cfg Config) IsProduction() bool {
	return cfg.Environment == EnvironmentProduction
}

// AllowsBootstrapData reports whether development seed data may run.
func (cfg Config) AllowsBootstrapData() bool {
	switch cfg.Environment {
	case EnvironmentLocal, EnvironmentDevelopment, EnvironmentTest:
		return true
	default:
		return false
	}
}

// PasswordCost returns the bcrypt cost used for password hashing.
func PasswordCost() int {
	return bcrypt.DefaultCost
}

// loadDatabaseURL returns DATABASE_URL when configured.
//
// In local development and tests, individual PostgreSQL variables receive
// development defaults. Staging and production receive no credential defaults.
func loadDatabaseURL(environment string) (string, error) {
	if databaseURL := env("DATABASE_URL", ""); databaseURL != "" {
		parsedURL, err := url.Parse(databaseURL)
		if err != nil {
			return "", fmt.Errorf("invalid DATABASE_URL: %w", err)
		}

		if parsedURL.Scheme == "" || parsedURL.Host == "" {
			return "", fmt.Errorf("invalid DATABASE_URL: missing scheme or host")
		}

		return databaseURL, nil
	}

	if environment == EnvironmentStaging ||
		environment == EnvironmentProduction {
		return "", nil
	}

	host := env("DB_HOST", "localhost")
	port := env("POSTGRES_PORT", "5432")
	name := env("POSTGRES_DB", "secureops")
	user := env("POSTGRES_USER", "secureops")
	password := env("POSTGRES_PASSWORD", "secureops")

	if err := validatePort("POSTGRES_PORT", port); err != nil {
		return "", err
	}

	if host == "" {
		return "", fmt.Errorf("DB_HOST cannot be empty")
	}

	if name == "" {
		return "", fmt.Errorf("POSTGRES_DB cannot be empty")
	}

	if user == "" {
		return "", fmt.Errorf("POSTGRES_USER cannot be empty")
	}

	databaseURL := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, password),
		Host:   net.JoinHostPort(host, port),
		Path:   name,
	}

	return databaseURL.String(), nil
}

// loadCorsAllowedOrigins uses localhost defaults only for local development
// and tests. Staging and production require explicit configuration.
func loadCorsAllowedOrigins(environment string) []string {
	value := env("CORS_ALLOWED_ORIGINS", "")
	if value == "" {
		value = env("CORS_ALLOWED_ORIGIN", "")
	}

	if value == "" {
		switch environment {
		case EnvironmentLocal, EnvironmentDevelopment, EnvironmentTest:
			value = defaultDevCorsAllowedOrigins
		}
	}

	return parseCSV(value)
}

// env returns a trimmed environment value or the supplied default.
func env(key string, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return defaultValue
	}

	return value
}

// normalizeEnvironment converts supported aliases to canonical environment
// names and rejects unknown values.
func normalizeEnvironment(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case EnvironmentLocal:
		return EnvironmentLocal, nil
	case "dev", EnvironmentDevelopment:
		return EnvironmentDevelopment, nil
	case EnvironmentTest:
		return EnvironmentTest, nil
	case "stage", EnvironmentStaging:
		return EnvironmentStaging, nil
	case "prod", EnvironmentProduction:
		return EnvironmentProduction, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrInvalidEnvironment, value)
	}
}

// boolFromEnvironment parses an optional boolean environment variable.
func boolFromEnvironment(
	key string,
	defaultValue bool,
) (bool, error) {
	raw, exists := os.LookupEnv(key)
	if !exists || strings.TrimSpace(raw) == "" {
		return defaultValue, nil
	}

	value, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return false, fmt.Errorf("%s must be a valid boolean: %w", key, err)
	}

	return value, nil
}

// durationFromMilliseconds parses a positive millisecond duration.
func durationFromMilliseconds(
	key string,
	defaultValue time.Duration,
) (time.Duration, error) {
	raw, exists := os.LookupEnv(key)
	if !exists || strings.TrimSpace(raw) == "" {
		return defaultValue, nil
	}

	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid integer: %w", key, err)
	}

	if value <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", key)
	}

	return time.Duration(value) * time.Millisecond, nil
}

// durationFromSeconds parses a positive second duration.
func durationFromSeconds(
	key string,
	defaultValue time.Duration,
) (time.Duration, error) {
	raw, exists := os.LookupEnv(key)
	if !exists || strings.TrimSpace(raw) == "" {
		return defaultValue, nil
	}

	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid integer: %w", key, err)
	}

	if value <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", key)
	}

	return time.Duration(value) * time.Second, nil
}

// validatePort validates a numeric TCP port.
func validatePort(key string, value string) error {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("%s must be a valid port number: %w", key, err)
	}

	if port < 1 || port > 65535 {
		return fmt.Errorf("%s must be between 1 and 65535", key)
	}

	return nil
}

// validateCORSOrigin ensures each configured origin is a specific HTTP or
// HTTPS origin rather than a wildcard or malformed URL.
func validateCORSOrigin(origin string) error {
	if origin == "*" {
		return fmt.Errorf(
			"CORS allowed origins must not contain a wildcard",
		)
	}

	parsed, err := url.ParseRequestURI(origin)
	if err != nil {
		return fmt.Errorf("invalid CORS origin %q: %w", origin, err)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf(
			"CORS origin %q must use http or https",
			origin,
		)
	}

	if parsed.Host == "" {
		return fmt.Errorf("CORS origin %q must include a host", origin)
	}

	if parsed.User != nil ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return fmt.Errorf(
			"CORS origin %q must not include credentials, a path, query, or fragment",
			origin,
		)
	}

	return nil
}

// parseCSV converts a comma-separated environment value into a deduplicated
// list.
func parseCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	entries := strings.Split(value, ",")
	values := make([]string, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if _, exists := seen[entry]; exists {
			continue
		}

		seen[entry] = struct{}{}
		values = append(values, entry)
	}

	return values
}
