// Package risk verifies shared risk helpers.
package risk

import (
	"testing"

	"blackradar/api/model"
)

func TestRiskFromSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		want     string
	}{
		{name: "critical", severity: "CRITICAL", want: "Critical"},
		{name: "high", severity: "High", want: "High"},
		{name: "medium", severity: "medium", want: "Medium"},
		{name: "unknown defaults low", severity: "informational", want: "Low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RiskFromSeverity(tt.severity); got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestRiskFromVulnerabilities(t *testing.T) {
	vulnerabilities := []model.Vulnerability{
		{Severity: "Low"},
		{Severity: "Critical"},
		{Severity: "Medium"},
	}

	if got := RiskFromVulnerabilities(vulnerabilities); got != "Critical" {
		t.Fatalf("expected Critical, got %q", got)
	}
}

func TestRiskPointerFromVulnerabilities(t *testing.T) {
	if got := RiskPointerFromVulnerabilities(nil); got != nil {
		t.Fatalf("expected nil risk pointer for empty vulnerabilities, got %#v", got)
	}

	vulnerabilities := []model.Vulnerability{{Severity: "High"}}
	got := RiskPointerFromVulnerabilities(vulnerabilities)
	if got == nil || *got != "High" {
		t.Fatalf("expected High risk level pointer, got %#v", got)
	}
}
