package providerquota

import (
	"errors"
	"fmt"
	"testing"
)

func TestProviderQuotaErrorsRemainClassifiable(t *testing.T) {
	if !errors.Is(fmt.Errorf("quota rejected: %w", ErrExceeded), ErrExceeded) {
		t.Fatal("expected quota exhaustion to remain classifiable after wrapping")
	}
	if !errors.Is(fmt.Errorf("quota store failed: %w", ErrUnavailable), ErrUnavailable) {
		t.Fatal("expected quota unavailability to remain classifiable after wrapping")
	}
}

func TestProviderNamesRemainStable(t *testing.T) {
	if OpenAI != "openai" || NVD != "nvd" {
		t.Fatalf("unexpected provider names: OpenAI=%q NVD=%q", OpenAI, NVD)
	}
}
