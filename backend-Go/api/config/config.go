// Package config loads application settings from environment variables.
// It provides structured configuration values for startup and middleware.
package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Config holds app settings loaded from environment variables.
type Config struct {
	Environment          string
	Port                 string
	DatabaseURL          string
	JWTSecret            string
	JWTExpiration        time.Duration
	JWTRefreshExpiration time.Duration
	JWTIssuer            string
	JWTAudience          string
	CorsAllowedOrigin    string
	NVDAPIBaseURL        string
	NVDCPEAPIBaseURL     string
	NVDAPIKey            string
	OpenAIAPIEndpoint    string
	OpenAIAPIKey         string
	OpenAIModel          string
	OpenAITimeout        time.Duration
	BootstrapDevData     bool
}

const nvdCVEAPIBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
const nvdCPEAPIBaseURL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
const openAIResponsesEndpoint = "https://api.openai.com/v1/responses"

// Load reads environment variables and fills default values for missing settings.
func Load() Config {
	environment := env("GO_ENV", "development")
	isProduction := environment == "production"

	port := env("PORT", "8080")
	databaseURL := env("DATABASE_URL", "")
	if databaseURL == "" {
		dbHost := env("DB_HOST", "localhost")
		dbPort := env("POSTGRES_PORT", "5432")
		dbName := env("POSTGRES_DB", "secureops")
		dbUser := env("POSTGRES_USER", "secureops")
		dbPassword := env("POSTGRES_PASSWORD", "secureops")

		if isProduction && (dbHost == "" || dbPort == "" || dbName == "" || dbUser == "" || dbPassword == "") {
			databaseURL = ""
		} else {
			databaseURL = fmt.Sprintf("postgres://%s:%s@%s:%s/%s", dbUser, dbPassword, dbHost, dbPort, dbName)
		}
	}

	jwtSecret := env("JWT_SECRET", "")
	jwtIssuer := env("JWT_ISSUER", "secureops")
	jwtAudience := env("JWT_AUDIENCE", "secureops-api")
	nvdAPIKey := env("NVD_API_KEY", "")
	openAIAPIKey := env("OPENAI_API_KEY", "")
	openAIModel := env("OPENAI_MODEL", "gpt-4.1-mini")
	bootstrapDevData := strings.EqualFold(env("BOOTSTRAP_DEV_DATA", "false"), "true")
	corsAllowedOrigin := env("CORS_ALLOWED_ORIGIN", "http://localhost:4200")
	if isProduction {
		corsAllowedOrigin = env("CORS_ALLOWED_ORIGIN", "")
	}

	expirationMs, err := strconv.Atoi(env("JWT_EXPIRATION_MS", "3600000"))
	if err != nil || expirationMs <= 0 {
		expirationMs = 3600000
	}
	refreshExpirationMs, err := strconv.Atoi(env("JWT_REFRESH_EXPIRATION_MS", "604800000"))
	if err != nil || refreshExpirationMs <= 0 {
		refreshExpirationMs = 604800000
	}
	openAITimeoutSeconds, err := strconv.Atoi(env("OPENAI_TIMEOUT_SECONDS", "20"))
	if err != nil || openAITimeoutSeconds <= 0 {
		openAITimeoutSeconds = 20
	}

	return Config{
		Environment:          environment,
		Port:                 port,
		DatabaseURL:          databaseURL,
		JWTSecret:            jwtSecret,
		JWTExpiration:        time.Duration(expirationMs) * time.Millisecond,
		JWTRefreshExpiration: time.Duration(refreshExpirationMs) * time.Millisecond,
		JWTIssuer:            jwtIssuer,
		JWTAudience:          jwtAudience,
		CorsAllowedOrigin:    corsAllowedOrigin,
		NVDAPIBaseURL:        nvdCVEAPIBaseURL,
		NVDCPEAPIBaseURL:     nvdCPEAPIBaseURL,
		NVDAPIKey:            nvdAPIKey,
		OpenAIAPIEndpoint:    openAIResponsesEndpoint,
		OpenAIAPIKey:         openAIAPIKey,
		OpenAIModel:          openAIModel,
		OpenAITimeout:        time.Duration(openAITimeoutSeconds) * time.Second,
		BootstrapDevData:     bootstrapDevData,
	}
}

// Validate checks that required production settings are present.
func (cfg Config) Validate() error {
	if cfg.Environment == "production" {
		if cfg.JWTSecret == "" {
			return ErrMissingJWTSecret
		}
		if cfg.CorsAllowedOrigin == "" {
			return ErrMissingCorsAllowedOrigin
		}
		if cfg.DatabaseURL == "" {
			return ErrMissingDatabaseURL
		}
	}
	return nil
}

// PasswordCost returns the bcrypt cost factor used for password hashing.
func PasswordCost() int {
	return bcrypt.DefaultCost
}
