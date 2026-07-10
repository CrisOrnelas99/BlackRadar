// Package repository verifies shared risk-level helpers.
package repository

import (
	"testing"

	"blackradar/api/model"
)

func TestRiskLevelFromSeverity(t *testing.T) {
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
			if got := RiskLevelFromSeverity(tt.severity); got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestRiskLevelFromVulnerabilities(t *testing.T) {
	vulnerabilities := []model.Vulnerability{
		{Severity: "Low"},
		{Severity: "Critical"},
		{Severity: "Medium"},
	}

	if got := RiskLevelFromVulnerabilities(vulnerabilities); got != "Critical" {
		t.Fatalf("expected Critical, got %q", got)
	}
}

func TestRiskLevelPointerFromVulnerabilities(t *testing.T) {
	if got := RiskLevelPointerFromVulnerabilities(nil); got != nil {
		t.Fatalf("expected nil risk level for empty vulnerabilities, got %#v", got)
	}

	vulnerabilities := []model.Vulnerability{{Severity: "High"}}
	got := RiskLevelPointerFromVulnerabilities(vulnerabilities)
	if got == nil || *got != "High" {
		t.Fatalf("expected High risk level pointer, got %#v", got)
	}
}
