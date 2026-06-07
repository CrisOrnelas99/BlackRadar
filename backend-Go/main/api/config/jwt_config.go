package config

import "time"

type JwtConfig struct {
	Secret     string
	Expiration time.Duration
}

