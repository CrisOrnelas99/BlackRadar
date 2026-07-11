package config

type ConfigError struct {
	Message string
}

func (e ConfigError) Error() string {
	return e.Message
}

var (
	ErrInvalidEnvironment        = &ConfigError{Message: "GO_ENV must be a supported environment"}
	ErrBootstrapNotAllowed       = &ConfigError{Message: "BOOTSTRAP_DEV_DATA cannot be enabled in this environment"}
	ErrMissingBootstrapPassword  = &ConfigError{Message: "BOOTSTRAP_DEV_PASSWORD is required when BOOTSTRAP_DEV_DATA is enabled"}
	ErrMissingJWTSecret          = &ConfigError{Message: "JWT_SECRET is required in production"}
	ErrMissingCorsAllowedOrigins = &ConfigError{Message: "CORS_ALLOWED_ORIGINS or CORS_ALLOWED_ORIGIN is required in production"}
	ErrMissingDatabaseURL        = &ConfigError{Message: "database connection settings are required in production"}
)
