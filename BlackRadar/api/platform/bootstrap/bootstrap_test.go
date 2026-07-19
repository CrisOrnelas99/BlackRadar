package bootstrap

import (
	"context"
	"errors"
	"testing"

	"blackradar/api/platform/config"
)

func TestRunSkipsWhenDisabled(t *testing.T) {
	cfg := config.Config{
		Environment:      config.EnvironmentProduction,
		BootstrapDevData: false,
	}

	if err := Run(context.Background(), nil, cfg); err != nil {
		t.Fatalf(
			"expected disabled bootstrap to skip without error, got %v",
			err,
		)
	}
}

func TestRunRejectsDisallowedEnvironment(t *testing.T) {
	disallowedEnvironments := []string{
		config.EnvironmentProduction,
		config.EnvironmentStaging,
		"",
		"sandbox",
	}

	for _, environment := range disallowedEnvironments {
		t.Run(environment, func(t *testing.T) {
			cfg := config.Config{
				Environment:          environment,
				BootstrapDevData:     true,
				BootstrapDevPassword: "LocalDevelopmentPassword123!",
			}

			err := Run(context.Background(), nil, cfg)
			if err == nil {
				t.Fatalf("expected environment %q to be rejected", environment)
			}

			if !errors.Is(err, config.ErrBootstrapNotAllowed) {
				t.Fatalf(
					"expected environment validation error, got %v",
					err,
				)
			}
		})
	}
}

func TestRunRejectsMissingDatabase(t *testing.T) {
	cfg := config.Config{
		Environment:          config.EnvironmentDevelopment,
		BootstrapDevData:     true,
		BootstrapDevPassword: "LocalDevelopmentPassword123!",
	}

	err := Run(context.Background(), nil, cfg)
	if err == nil {
		t.Fatal("expected missing database to fail")
	}

	if !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected missing database error, got %v", err)
	}
}

func TestRunRejectsMissingBootstrapPassword(t *testing.T) {
	cfg := config.Config{
		Environment:      config.EnvironmentDevelopment,
		BootstrapDevData: true,
	}

	err := Run(context.Background(), nil, cfg)
	if err == nil {
		t.Fatal("expected missing bootstrap password to fail")
	}

	if !errors.Is(err, config.ErrMissingBootstrapPassword) &&
		!errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected bootstrap password or database validation error, got %v", err)
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase value",
			input:    "development",
			expected: "development",
		},
		{
			name:     "uppercase value",
			input:    "DEVELOPMENT",
			expected: "development",
		},
		{
			name:     "surrounding whitespace",
			input:    "  Development  ",
			expected: "development",
		},
		{
			name:     "empty value",
			input:    "",
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := normalize(test.input)
			if actual != test.expected {
				t.Fatalf(
					"expected %q, got %q",
					test.expected,
					actual,
				)
			}
		})
	}
}
