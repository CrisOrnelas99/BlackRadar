// Package config loads and validates application settings from environment
// variables.
package config

import (
	"errors"
	"time"
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

	minimumJWTSecretLength = 32
)

var (
	ErrInvalidEnvironment        = errors.New("GO_ENV must be a supported environment")
	ErrBootstrapNotAllowed       = errors.New("BOOTSTRAP_DEV_DATA cannot be enabled in this environment")
	ErrMissingBootstrapPassword  = errors.New("BOOTSTRAP_DEV_PASSWORD is required when BOOTSTRAP_DEV_DATA is enabled")
	ErrMissingJWTSecret          = errors.New("JWT_SECRET is required")
	ErrMissingCorsAllowedOrigins = errors.New("CORS_ALLOWED_ORIGINS or CORS_ALLOWED_ORIGIN is required in production")
	ErrMissingDatabaseURL        = errors.New("database connection settings are required in production")
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
	TrustedProxyCIDRs  []string

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
		TrustedProxyCIDRs:  parseCSV(env("TRUSTED_PROXY_CIDRS", "")),

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
