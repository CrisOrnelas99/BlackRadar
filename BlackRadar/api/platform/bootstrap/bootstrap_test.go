package bootstrap

import (
	"context"
	"errors"
	"testing"

	"blackradar/api/model"
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

func TestNewBootstrapUserUsesFixedLocalAdministratorIdentity(t *testing.T) {
	user := newBootstrapUser("test-password-hash")

	if user.ID != bootstrapUserID {
		t.Fatalf("unexpected bootstrap user ID %q", user.ID)
	}
	if user.FullName != bootstrapFullName || user.Username != bootstrapUsername {
		t.Fatalf("unexpected bootstrap user identity: %#v", user)
	}
	if user.Email != bootstrapEmail || user.Role != model.RoleMaster {
		t.Fatalf("unexpected bootstrap user access fields: email=%q role=%q", user.Email, user.Role)
	}
	if user.PasswordHash != "test-password-hash" {
		t.Fatalf("unexpected bootstrap password hash %q", user.PasswordHash)
	}
}

func TestNewBootstrapAssetSupportsWindowsAppCVEScanWithoutAssignments(t *testing.T) {
	asset := newBootstrapAsset(bootstrapUserID, bootstrapAssessmentID)

	if asset.Name != "Microsoft Windows App Client" {
		t.Fatalf("unexpected bootstrap asset name %q", asset.Name)
	}
	if asset.Criticality != "Medium" || asset.RiskLevel == nil || *asset.RiskLevel != "Low" {
		t.Fatalf("unexpected bootstrap risk fields: criticality=%q risk=%v", asset.Criticality, asset.RiskLevel)
	}
	if asset.Type != "Application" || asset.Vendor == nil || *asset.Vendor != "Microsoft" {
		t.Fatalf("unexpected bootstrap product class: type=%q vendor=%v", asset.Type, asset.Vendor)
	}
	if asset.Product == nil || *asset.Product != "Windows App" || asset.Version == nil || *asset.Version != "2.0.1313" {
		t.Fatalf("unexpected bootstrap product fingerprint: product=%v version=%v", asset.Product, asset.Version)
	}
	if len(asset.Vulnerabilities) != 0 {
		t.Fatalf("expected no bootstrap vulnerability assignments, got %d", len(asset.Vulnerabilities))
	}
}
