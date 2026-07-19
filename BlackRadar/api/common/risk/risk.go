// Package risk provides shared asset risk calculation rules.
package risk

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"blackradar/api/model"
)

var (
	ErrDatabaseRequired = errors.New("asset risk backfill requires a database connection")
	ErrLoadAssetsFailed = errors.New("asset risk backfill failed to load assets")
	ErrRefreshFailed    = errors.New("asset risk backfill failed to refresh asset risk")
)

type assetRow struct {
	ID             string `gorm:"column:id"`
	OrganizationID string `gorm:"column:organization_id"`
}

// loadAssetRows loads the assets that need risk recalculation.
var loadAssetRows = func(ctx context.Context, database *gorm.DB) ([]assetRow, error) {
	var assets []assetRow
	if err := database.WithContext(ctx).Table("assets").Select("id, organization_id").Order("id").Find(&assets).Error; err != nil {
		return nil, err
	}
	return assets, nil
}

// runBackfillTransaction runs the risk backfill inside one database transaction.
var runBackfillTransaction = func(ctx context.Context, database *gorm.DB, fn func(tx *gorm.DB) error) error {
	return database.WithContext(ctx).Transaction(fn)
}

// refreshAssetRisk recalculates and persists one asset's risk level.
var refreshAssetRisk = func(tx *gorm.DB, assetID string, organizationID string) error {
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
		Update("risk_level", PointerFromVulnerabilities(vulnerabilities)).Error
}

// FromSeverity maps a vulnerability severity to the corresponding asset risk level.
func FromSeverity(severity string) string {
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

// FromVulnerabilities returns the highest risk level implied by the supplied vulnerabilities.
func FromVulnerabilities(vulnerabilities []model.Vulnerability) string {
	riskLevel := "Low"
	for _, vulnerability := range vulnerabilities {
		current := FromSeverity(vulnerability.Severity)
		if rank(current) > rank(riskLevel) {
			riskLevel = current
		}
	}
	return riskLevel
}

// PointerFromVulnerabilities returns nil when no vulnerabilities are attached.
func PointerFromVulnerabilities(vulnerabilities []model.Vulnerability) *string {
	if len(vulnerabilities) == 0 {
		return nil
	}

	riskLevel := FromVulnerabilities(vulnerabilities)
	return &riskLevel
}

// BackfillAssetRiskLevels recalculates stored risk levels for existing assets.
//
// This is a startup data fix for rows created before risk became nullable
// and derived from attached vulnerabilities.
func BackfillAssetRiskLevels(ctx context.Context, database *gorm.DB) error {
	if database == nil {
		return ErrDatabaseRequired
	}

	assets, err := loadAssetRows(ctx, database)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLoadAssetsFailed, err)
	}

	return runBackfillTransaction(ctx, database, func(tx *gorm.DB) error {
		for _, asset := range assets {
			if err := refreshAssetRisk(tx, asset.ID, asset.OrganizationID); err != nil {
				return fmt.Errorf(
					"%w: asset %s: %w",
					ErrRefreshFailed,
					asset.ID,
					err,
				)
			}
		}
		return nil
	})
}

// rank returns the ordering weight for a normalized risk level.
func rank(riskLevel string) int {
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
