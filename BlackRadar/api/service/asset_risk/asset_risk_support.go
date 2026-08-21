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

// CalculateRiskLevel combines asset criticality with the highest active vulnerability severity.
func CalculateRiskLevel(criticality string, vulnerabilities []model.Vulnerability) *string {
	if len(vulnerabilities) == 0 {
		riskLevel := "Low"
		return &riskLevel
	}

	assetRank := riskRank(riskLevelFromCriticality(criticality))
	highestVulnerabilityRank := riskRank("Low")
	for _, vulnerability := range vulnerabilities {
		currentRank := riskRank(riskLevelFromSeverity(vulnerability.Severity))
		if currentRank > highestVulnerabilityRank {
			highestVulnerabilityRank = currentRank
		}
	}

	// Add one before integer division to round .5 values upward.
	riskLevel := riskLevelFromRank((assetRank + highestVulnerabilityRank + 1) / 2)
	return &riskLevel
}

// riskLevelFromCriticality normalizes an asset's criticality to a risk level.
func riskLevelFromCriticality(criticality string) string {
	return riskLevelFromSeverity(criticality)
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

// riskLevelFromRank maps a numeric risk score back to its display level.
func riskLevelFromRank(rank int) string {
	switch rank {
	case 4:
		return "Critical"
	case 3:
		return "High"
	case 2:
		return "Medium"
	default:
		return "Low"
	}
}
