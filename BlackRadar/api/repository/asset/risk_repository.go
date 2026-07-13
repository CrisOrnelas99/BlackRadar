// Package repository provides asset persistence operations.
package repository

import (
	"strings"

	"gorm.io/gorm"

	"blackradar/api/model"
)

// RiskFromSeverity maps a vulnerability severity to the corresponding asset risk level.
func RiskFromSeverity(severity string) string {
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

// RiskFromVulnerabilities returns the highest risk level implied by the supplied vulnerabilities.
func RiskFromVulnerabilities(vulnerabilities []model.Vulnerability) string {
	riskLevel := "Low"
	for _, vulnerability := range vulnerabilities {
		current := RiskFromSeverity(vulnerability.Severity)
		if riskRank(current) > riskRank(riskLevel) {
			riskLevel = current
		}
	}
	return riskLevel
}

// RiskPointerFromVulnerabilities returns nil when no vulnerabilities are attached.
func RiskPointerFromVulnerabilities(vulnerabilities []model.Vulnerability) *string {
	if len(vulnerabilities) == 0 {
		return nil
	}

	riskLevel := RiskFromVulnerabilities(vulnerabilities)
	return &riskLevel
}

// RefreshAssetRisk recalculates and persists the risk level for a single asset.
func RefreshAssetRisk(tx *gorm.DB, assetID string, organizationID string) error {
	var asset model.Asset
	if err := tx.Where("organization_id = ?", organizationID).
		First(&asset, assetID).Error; err != nil {
		return err
	}

	var vulnerabilities []model.Vulnerability
	if err := tx.Model(&model.Vulnerability{}).
		Joins("JOIN asset_vulnerabilities av ON av.vulnerability_id = vulnerabilities.id AND av.deleted_at IS NULL").
		Where("av.asset_id = ? AND vulnerabilities.organization_id = ?", assetID, organizationID).
		Find(&vulnerabilities).Error; err != nil {
		return err
	}

	return tx.Model(&model.Asset{}).
		Where("id = ? AND organization_id = ?", assetID, organizationID).
		Update("risk_level", RiskPointerFromVulnerabilities(vulnerabilities)).Error
}

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
