package bootstrap

import (
	"context"
	"strings"
	"testing"

	"blackradar/api/config"
)

func TestRunSkipsWhenDisabled(t *testing.T) {
	cfg := config.Config{
		Environment:      "production",
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
	tests := []struct {
		name        string
		environment string
	}{
		{
			name:        "production",
			environment: "production",
		},
		{
			name:        "production with uppercase characters",
			environment: "PRODUCTION",
		},
		{
			name:        "staging",
			environment: "staging",
		},
		{
			name:        "empty environment",
			environment: "",
		},
		{
			name:        "unknown environment",
			environment: "sandbox",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := config.Config{
				Environment:      test.environment,
				BootstrapDevData: true,
			}

			err := Run(context.Background(), nil, cfg)
			if err == nil {
				t.Fatalf(
					"expected environment %q to be rejected",
					test.environment,
				)
			}

			if !strings.Contains(
				err.Error(),
				"bootstrap dev data is not allowed",
			) {
				t.Fatalf(
					"expected environment validation error, got %v",
					err,
				)
			}
		})
	}

}

func TestRunAcceptsEnvironmentCaseAndWhitespace(t *testing.T) {
	cfg := config.Config{
		Environment:      "  DEVELOPMENT  ",
		BootstrapDevData: true,
	}

	err := Run(context.Background(), nil, cfg)
	if err == nil {
		t.Fatal("expected missing database error")
	}

	if !strings.Contains(err.Error(), "database is required") {
		t.Fatalf(
			"expected environment to be accepted before database validation, got %v",
			err,
		)
	}

}

func TestRunRejectsMissingDatabase(t *testing.T) {
	cfg := config.Config{
		Environment:      "development",
		BootstrapDevData: true,
	}

	err := Run(context.Background(), nil, cfg)
	if err == nil {
		t.Fatal("expected missing database to fail")
	}

	if !strings.Contains(err.Error(), "database is required") {
		t.Fatalf("expected missing database error, got %v", err)
	}

}

func TestValidateBootstrapEnvironmentAcceptsAllowedEnvironments(
	t *testing.T,
) {
	allowedEnvironments := []string{
		"local",
		"development",
		"dev",
		"test",
		" LOCAL ",
		"Development",
		"DEV",
		" Test ",
	}

	for _, environment := range allowedEnvironments {
		t.Run(environment, func(t *testing.T) {
			if err := validateBootstrapEnvironment(environment); err != nil {
				t.Fatalf(
					"expected environment %q to be allowed, got %v",
					environment,
					err,
				)
			}
		})
	}

}

func TestValidateBootstrapEnvironmentRejectsDisallowedEnvironments(
	t *testing.T,
) {
	disallowedEnvironments := []string{
		"",
		"production",
		"prod",
		"staging",
		"qa",
		"production-us",
	}

	for _, environment := range disallowedEnvironments {
		t.Run(environment, func(t *testing.T) {
			err := validateBootstrapEnvironment(environment)
			if err == nil {
				t.Fatalf(
					"expected environment %q to be rejected",
					environment,
				)
			}
		})
	}

}

func TestBootstrapPasswordReturnsConfiguredPassword(t *testing.T) {
	const expectedPassword = "LocalDevelopmentPassword123!"

	t.Setenv(
		bootstrapPasswordEnvironmentVariable,
		expectedPassword,
	)

	password, err := bootstrapPassword()
	if err != nil {
		t.Fatalf("expected configured password, got error %v", err)
	}

	if password != expectedPassword {
		t.Fatalf(
			"expected password %q, got %q",
			expectedPassword,
			password,
		)
	}

}

func TestBootstrapPasswordTrimsWhitespace(t *testing.T) {
	t.Setenv(
		bootstrapPasswordEnvironmentVariable,
		"  LocalDevelopmentPassword123!  ",
	)

	password, err := bootstrapPassword()
	if err != nil {
		t.Fatalf("expected configured password, got error %v", err)
	}

	if password != "LocalDevelopmentPassword123!" {
		t.Fatalf("expected trimmed password, got %q", password)
	}

}

func TestBootstrapPasswordRejectsMissingPassword(t *testing.T) {
	t.Setenv(bootstrapPasswordEnvironmentVariable, "")

	_, err := bootstrapPassword()
	if err == nil {
		t.Fatal("expected missing bootstrap password to fail")
	}

	if !strings.Contains(
		err.Error(),
		bootstrapPasswordEnvironmentVariable,
	) {
		t.Fatalf(
			"expected error to mention %s, got %v",
			bootstrapPasswordEnvironmentVariable,
			err,
		)
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
