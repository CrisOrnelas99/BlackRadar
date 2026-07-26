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
	ID     string `gorm:"column:id"`
	UserID string `gorm:"column:user_id"`
}

type backfillOperations struct {
	loadAssets       func(ctx context.Context, database *gorm.DB) ([]assetRow, error)
	runTransaction   func(ctx context.Context, database *gorm.DB, fn func(tx *gorm.DB) error) error
	refreshAssetRisk func(tx *gorm.DB, assetID string, userID string) error
}

func defaultBackfillOperations() backfillOperations {
	return backfillOperations{
		loadAssets:       loadAssetRows,
		runTransaction:   runBackfillTransaction,
		refreshAssetRisk: refreshAssetRisk,
	}
}

// loadAssetRows loads the assets that need risk recalculation.
func loadAssetRows(ctx context.Context, database *gorm.DB) ([]assetRow, error) {
	var assets []assetRow
	if err := database.WithContext(ctx).Table("assets").Select("id, user_id").Order("id").Find(&assets).Error; err != nil {
		return nil, err
	}
	return assets, nil
}

// runBackfillTransaction runs the risk backfill inside one database transaction.
func runBackfillTransaction(ctx context.Context, database *gorm.DB, fn func(tx *gorm.DB) error) error {
	return database.WithContext(ctx).Transaction(fn)
}

// refreshAssetRisk recalculates and persists one asset's risk level.
func refreshAssetRisk(tx *gorm.DB, assetID string, userID string) error {
	var asset model.Asset
	if err := tx.Where("user_id = ? AND id = ?", userID, assetID).
		First(&asset).Error; err != nil {
		return err
	}

	var vulnerabilities []model.Vulnerability
	if err := tx.Model(&model.Vulnerability{}).
		Joins("JOIN asset_vulnerabilities av ON av.vulnerability_id = vulnerabilities.id AND av.deleted_at IS NULL").
		Where("av.asset_id = ? AND vulnerabilities.user_id = ?", assetID, userID).
		Find(&vulnerabilities).Error; err != nil {
		return err
	}

	return tx.Model(&model.Asset{}).
		Where("id = ? AND user_id = ?", assetID, userID).
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
	return backfillAssetRiskLevels(ctx, database, defaultBackfillOperations())
}

func backfillAssetRiskLevels(ctx context.Context, database *gorm.DB, operations backfillOperations) error {
	if database == nil {
		return ErrDatabaseRequired
	}

	assets, err := operations.loadAssets(ctx, database)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLoadAssetsFailed, err)
	}

	return operations.runTransaction(ctx, database, func(tx *gorm.DB) error {
		for _, asset := range assets {
			if err := operations.refreshAssetRisk(tx, asset.ID, asset.UserID); err != nil {
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
