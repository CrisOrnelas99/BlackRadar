// Package repository provides asset-risk persistence operations.
package repository

import (
	"context"
	"fmt"

	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"

	"gorm.io/gorm"
)

// AssetRiskRepository persists derived asset risk state.
type AssetRiskRepository struct {
	db *gorm.DB
}

// NewAssetRiskRepository creates an asset-risk repository backed by the supplied database.
func NewAssetRiskRepository(db *gorm.DB) *AssetRiskRepository {
	return &AssetRiskRepository{db: db}
}

// FindActiveVulnerabilitiesForUser loads active vulnerabilities assigned to an owned asset.
func (r *AssetRiskRepository) FindActiveVulnerabilitiesForUser(ec *appcontext.GinContext, assetID string, userID string) ([]model.Vulnerability, error) {
	var vulnerabilities []model.Vulnerability
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Model(&model.Vulnerability{}).
		Joins("JOIN asset_vulnerabilities av ON av.vulnerability_id = vulnerabilities.id AND av.deleted_at IS NULL").
		Joins("JOIN assets a ON a.id = av.asset_id AND a.user_id = ?", userID).
		Where("av.asset_id = ? AND vulnerabilities.user_id = ?", assetID, userID).
		Order("vulnerabilities.id").
		Find(&vulnerabilities).Error
	if err != nil {
		return nil, fmt.Errorf("%w: load active vulnerabilities: %w", ErrPersistenceFailure, err)
	}
	return vulnerabilities, nil
}

// FindAssignedAssetIDsForVulnerability returns active owned asset relationships.
func (r *AssetRiskRepository) FindAssignedAssetIDsForVulnerability(ec *appcontext.GinContext, vulnerabilityID string, userID string) ([]string, error) {
	var assetIDs []string
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Table("assets").
		Select("assets.id").
		Joins("JOIN asset_vulnerabilities av ON av.asset_id = assets.id AND av.deleted_at IS NULL").
		Where("assets.user_id = ? AND av.vulnerability_id = ?", userID, vulnerabilityID).
		Order("assets.id").
		Pluck("assets.id", &assetIDs).Error
	if err != nil {
		return nil, fmt.Errorf("%w: load assigned assets: %w", ErrPersistenceFailure, err)
	}
	return assetIDs, nil
}

// UpdateRiskLevelForUser persists a derived risk level for an owned asset.
func (r *AssetRiskRepository) UpdateRiskLevelForUser(ec *appcontext.GinContext, assetID string, userID string, riskLevel *string) error {
	result := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Model(&model.Asset{}).
		Where("id = ? AND user_id = ?", assetID, userID).
		Update("risk_level", riskLevel)
	if result.Error != nil {
		return fmt.Errorf("%w: update risk level: %w", ErrPersistenceFailure, result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrRecordNotFound
	}
	return nil
}

// BackfillAssetRiskLevels recalculates every asset risk level in one transaction.
func (r *AssetRiskRepository) BackfillAssetRiskLevels(ctx context.Context, calculate func([]model.Vulnerability) *string) error {
	if r.db == nil {
		return ErrDatabaseRequired
	}
	if calculate == nil {
		return ErrCalculatorRequired
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var assets []model.Asset
		if err := tx.Select("id, user_id").Order("id").Find(&assets).Error; err != nil {
			return fmt.Errorf("%w: load assets: %w", ErrPersistenceFailure, err)
		}

		for _, asset := range assets {
			var vulnerabilities []model.Vulnerability
			if err := tx.Model(&model.Vulnerability{}).
				Joins("JOIN asset_vulnerabilities av ON av.vulnerability_id = vulnerabilities.id AND av.deleted_at IS NULL").
				Where("av.asset_id = ? AND vulnerabilities.user_id = ?", asset.ID, asset.UserID).
				Find(&vulnerabilities).Error; err != nil {
				return fmt.Errorf("%w: load asset %s vulnerabilities: %w", ErrPersistenceFailure, asset.ID, err)
			}

			if err := tx.Model(&model.Asset{}).
				Where("id = ? AND user_id = ?", asset.ID, asset.UserID).
				Update("risk_level", calculate(vulnerabilities)).Error; err != nil {
				return fmt.Errorf("%w: update asset %s risk level: %w", ErrPersistenceFailure, asset.ID, err)
			}
		}
		return nil
	})
}

// dbForContext returns the request-scoped database when present, otherwise the repository database.
func (r *AssetRiskRepository) dbForContext(ec *appcontext.GinContext) *gorm.DB {
	if ec != nil && ec.Database() != nil {
		return ec.Database()
	}
	return r.db
}
