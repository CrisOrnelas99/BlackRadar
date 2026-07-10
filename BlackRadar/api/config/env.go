// Package config provides internal helpers for reading process environment values.
package config

import "os"

// env returns the environment variable value or a fallback if it is not set.
func env(key string, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
