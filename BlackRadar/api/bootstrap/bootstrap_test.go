package bootstrap

import (
	"context"
	"strings"
	"testing"

	"blackradar/api/config"
)

func TestRunSkipsWhenDisabled(t *testing.T) {
	cfg := config.Config{
		Environment:      "development",
		BootstrapDevData: false,
	}

	if err := Run(context.Background(), nil, cfg); err != nil {
		t.Fatalf("expected disabled bootstrap to skip without error, got %v", err)
	}
}

func TestRunRejectsProduction(t *testing.T) {
	cfg := config.Config{
		Environment:      "production",
		BootstrapDevData: true,
	}

	err := Run(context.Background(), nil, cfg)
	if err == nil {
		t.Fatal("expected production bootstrap to fail")
	}
	if !strings.Contains(err.Error(), "production") {
		t.Fatalf("expected production error, got %v", err)
	}
}
