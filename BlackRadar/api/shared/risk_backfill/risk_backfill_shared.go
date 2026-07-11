// Package risk_backfill provides startup helpers to backfill asset risk values.
package risk_backfill

import (
	"context"

	"gorm.io/gorm"

	riskrepo "blackradar/api/repository/risk"
)

type assetRow struct {
	ID             string `gorm:"column:id"`
	OrganizationID string `gorm:"column:organization_id"`
}

var loadAssetRows = func(ctx context.Context, database *gorm.DB) ([]assetRow, error) {
	var assets []assetRow
	if err := database.WithContext(ctx).Table("assets").Select("id, organization_id").Order("id").Find(&assets).Error; err != nil {
		return nil, err
	}
	return assets, nil
}

var runBackfillTransaction = func(ctx context.Context, database *gorm.DB, fn func(tx *gorm.DB) error) error {
	return database.WithContext(ctx).Transaction(fn)
}

var refreshAssetRisk = riskrepo.RefreshAssetRisk

// BackfillAssetRiskLevels recalculates stored risk levels for existing assets.
//
// This is a startup data fix for rows created before risk became nullable
// and derived from attached vulnerabilities.
func BackfillAssetRiskLevels(ctx context.Context, database *gorm.DB) error {
	assets, err := loadAssetRows(ctx, database)
	if err != nil {
		return err
	}

	return runBackfillTransaction(ctx, database, func(tx *gorm.DB) error {
		for _, asset := range assets {
			if err := refreshAssetRisk(tx, asset.ID, asset.OrganizationID); err != nil {
				return err
			}
		}
		return nil
	})
}
