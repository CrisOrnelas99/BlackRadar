// Package utils provides database connection, migration, and error translation helpers.
package utils

import (
	"context"

	"gorm.io/gorm"

	baserepository "secureops/backend-go/api/repository"
)

// BackfillAssetRiskLevels recalculates stored risk levels for existing assets.
//
// This is a startup data fix for rows created before risk_level became nullable
// and derived from attached vulnerabilities.
func BackfillAssetRiskLevels(ctx context.Context, database *gorm.DB) error {
	type assetRow struct {
		ID             int64 `gorm:"column:id"`
		OrganizationID int64 `gorm:"column:organization_id"`
	}

	var assets []assetRow
	if err := database.WithContext(ctx).Table("assets").Select("id, organization_id").Order("id").Find(&assets).Error; err != nil {
		return err
	}

	return database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, asset := range assets {
			if err := baserepository.RefreshAssetRiskLevel(tx, asset.ID, asset.OrganizationID); err != nil {
				return err
			}
		}
		return nil
	})
}
