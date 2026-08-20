package service

import (
	"testing"

	"blackradar/api/model"
)

func TestCalculateRiskLevelCombinesCriticalityAndHighestSeverity(t *testing.T) {
	vulnerabilities := []model.Vulnerability{
		{Severity: "Low"},
		{Severity: "medium"},
		{Severity: "CRITICAL"},
	}

	got := CalculateRiskLevel("Low", vulnerabilities)
	if got == nil || *got != "High" {
		t.Fatalf("expected High risk level, got %#v", got)
	}
}

func TestCalculateRiskLevelUsesAssetCriticality(t *testing.T) {
	tests := []struct {
		name         string
		criticality  string
		severity     string
		expectedRisk string
	}{
		{name: "high asset low vulnerability", criticality: "High", severity: "Low", expectedRisk: "Medium"},
		{name: "high asset critical vulnerability", criticality: "High", severity: "Critical", expectedRisk: "Critical"},
		{name: "critical asset critical vulnerability", criticality: "Critical", severity: "Critical", expectedRisk: "Critical"},
		{name: "low asset without vulnerabilities", criticality: "Low", expectedRisk: "Low"},
		{name: "high asset without vulnerabilities", criticality: "High", expectedRisk: "Low"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var vulnerabilities []model.Vulnerability
			if test.severity != "" {
				vulnerabilities = []model.Vulnerability{{Severity: test.severity}}
			}
			got := CalculateRiskLevel(test.criticality, vulnerabilities)
			if got == nil || *got != test.expectedRisk {
				t.Fatalf("expected %s risk level, got %#v", test.expectedRisk, got)
			}
		})
	}
}
