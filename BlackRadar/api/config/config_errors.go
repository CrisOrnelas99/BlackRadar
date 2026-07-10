package config

type ConfigError struct {
	Message string
}

func (e ConfigError) Error() string {
	return e.Message
}

var (
	ErrMissingJWTSecret          = &ConfigError{Message: "JWT_SECRET is required in production"}
	ErrMissingCorsAllowedOrigins = &ConfigError{Message: "CORS_ALLOWED_ORIGINS or CORS_ALLOWED_ORIGIN is required in production"}
	ErrMissingDatabaseURL        = &ConfigError{Message: "database connection settings are required in production"}
)
