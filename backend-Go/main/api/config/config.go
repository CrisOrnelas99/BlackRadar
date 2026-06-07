package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port          string
	DatabaseURL   string
	JWTSecret     string
	JWTExpiration time.Duration
}

func Load() Config {
	port := env("PORT", "8080")
	dbHost := env("DB_HOST", "localhost")
	dbPort := env("POSTGRES_PORT", "5432")
	dbName := env("POSTGRES_DB", "secureops")
	dbUser := env("POSTGRES_USER", "secureops")
	dbPassword := env("POSTGRES_PASSWORD", "secureops")
	jwtSecret := env("JWT_SECRET", "")

	expirationMs, _ := strconv.Atoi(env("JWT_EXPIRATION_MS", "3600000"))

	return Config{
		Port:          port,
		DatabaseURL:   fmt.Sprintf("postgres://%s:%s@%s:%s/%s", dbUser, dbPassword, dbHost, dbPort, dbName),
		JWTSecret:     jwtSecret,
		JWTExpiration: time.Duration(expirationMs) * time.Millisecond,
	}
}

func env(key string, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

