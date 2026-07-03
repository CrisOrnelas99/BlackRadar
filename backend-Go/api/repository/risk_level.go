// Package repository defines shared persistence helpers used by feature repositories.
package repository

import (
	"strings"

	"gorm.io/gorm"

	"secureops/backend-go/api/model"
)

// RiskLevelFromSeverity maps a vulnerability severity to the corresponding asset risk level.
func RiskLevelFromSeverity(severity string) string {
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

// RiskLevelFromVulnerabilities returns the highest risk level implied by the supplied vulnerabilities.
func RiskLevelFromVulnerabilities(vulnerabilities []model.Vulnerability) string {
	riskLevel := "Low"
	for _, vulnerability := range vulnerabilities {
		current := RiskLevelFromSeverity(vulnerability.Severity)
		if riskLevelRank(current) > riskLevelRank(riskLevel) {
			riskLevel = current
		}
	}
	return riskLevel
}

// RiskLevelPointerFromVulnerabilities returns nil when no vulnerabilities are attached.
func RiskLevelPointerFromVulnerabilities(vulnerabilities []model.Vulnerability) *string {
	if len(vulnerabilities) == 0 {
		return nil
	}

	riskLevel := RiskLevelFromVulnerabilities(vulnerabilities)
	return &riskLevel
}

// RefreshAssetRiskLevel recalculates and persists the risk level for a single asset.
func RefreshAssetRiskLevel(tx *gorm.DB, assetID int64, organizationID int64) error {
	var asset model.Asset
	if err := tx.Preload("Vulnerabilities", "organization_id = ?", organizationID).
		Where("organization_id = ?", organizationID).
		First(&asset, assetID).Error; err != nil {
		return err
	}

	return tx.Model(&model.Asset{}).
		Where("id = ? AND organization_id = ?", assetID, organizationID).
		Update("risk_level", RiskLevelPointerFromVulnerabilities(asset.Vulnerabilities)).Error
}

func riskLevelRank(riskLevel string) int {
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
