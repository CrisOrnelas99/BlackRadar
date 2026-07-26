package service

import (
	"testing"

	"blackradar/api/model"
)

func TestCalculateRiskLevelReturnsNilWithoutActiveVulnerabilities(t *testing.T) {
	if got := CalculateRiskLevel(nil); got != nil {
		t.Fatalf("expected nil risk level, got %v", *got)
	}
}

func TestCalculateRiskLevelReturnsHighestSeverity(t *testing.T) {
	vulnerabilities := []model.Vulnerability{
		{Severity: "Low"},
		{Severity: "medium"},
		{Severity: "CRITICAL"},
	}

	got := CalculateRiskLevel(vulnerabilities)
	if got == nil || *got != "Critical" {
		t.Fatalf("expected Critical risk level, got %#v", got)
	}
}

func TestCalculateRiskLevelDefaultsUnknownSeverityToLow(t *testing.T) {
	got := CalculateRiskLevel([]model.Vulnerability{{Severity: "informational"}})
	if got == nil || *got != "Low" {
		t.Fatalf("expected Low risk level, got %#v", got)
	}
}
