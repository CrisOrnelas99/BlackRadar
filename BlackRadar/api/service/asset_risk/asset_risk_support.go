// Package service support contains deterministic asset-risk calculation rules.
package service

import (
	"errors"
	"fmt"
	"strings"

	"blackradar/api/model"
	assetriskrepository "blackradar/api/repository/asset_risk"
)

// translateAssetRiskRepositoryError maps persistence failures to service errors.
func translateAssetRiskRepositoryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, assetriskrepository.ErrRecordNotFound):
		return fmt.Errorf("%w: %w", ErrAssetRiskNotFound, err)
	default:
		return fmt.Errorf("%w: %w", ErrAssetRiskDependency, err)
	}
}

// CalculateRiskLevel returns nil for an asset without active vulnerabilities.
func CalculateRiskLevel(vulnerabilities []model.Vulnerability) *string {
	if len(vulnerabilities) == 0 {
		return nil
	}

	riskLevel := "Low"
	for _, vulnerability := range vulnerabilities {
		current := riskLevelFromSeverity(vulnerability.Severity)
		if riskRank(current) > riskRank(riskLevel) {
			riskLevel = current
		}
	}

	return &riskLevel
}

// riskLevelFromSeverity maps a vulnerability severity to an asset risk level.
func riskLevelFromSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	default:
		return "Low"
	}
}

// riskRank returns the ordering weight for a normalized risk level.
func riskRank(riskLevel string) int {
	switch riskLevel {
	case "Critical":
		return 4
	case "High":
		return 3
	case "Medium":
		return 2
	case "Low":
		return 1
	default:
		return 0
	}
}
