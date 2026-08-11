// Package repository provides asset persistence operations.
package repository

import (
	"errors"
	"fmt"
	"strings"

	commonid "blackradar/api/common/id"
	"blackradar/api/model"
	platformdb "blackradar/api/platform/db"
	appcontext "blackradar/api/platform/requestcontext"

	"gorm.io/gorm"
)

// AssetRepository persists asset records.
type AssetRepository struct {
	db *gorm.DB
}

// NewAssetRepository creates an asset repository backed by the supplied database.
func NewAssetRepository(db *gorm.DB) *AssetRepository {
	return &AssetRepository{db: db}
}

// FindAllByUser returns all assets owned by the specified user.
func (r *AssetRepository) FindAllByUser(ec *appcontext.GinContext, userID string) ([]model.Asset, error) {
	var assets []model.Asset
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Preload("Assessment").
		Where("user_id = ?", userID).
		Order("id").
		Find(&assets).Error
	if err != nil {
		return nil, fmt.Errorf("%w: read assets: %w", ErrPersistenceFailure, err)
	}
	if err := r.loadVulnerabilityCounts(ec, assets, userID); err != nil {
		return nil, err
	}
	return assets, nil
}

// loadVulnerabilityCounts adds active vulnerability counts to owned assets.
func (r *AssetRepository) loadVulnerabilityCounts(ec *appcontext.GinContext, assets []model.Asset, userID string) error {
	if len(assets) == 0 {
		return nil
	}

	type vulnerabilityCount struct {
		AssetID string
		Count   int64
	}

	assetIDs := make([]string, 0, len(assets))
	for _, asset := range assets {
		assetIDs = append(assetIDs, asset.ID)
	}

	var counts []vulnerabilityCount
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Table("asset_vulnerabilities av").
		Select("av.asset_id, COUNT(*) AS count").
		Joins("JOIN vulnerabilities v ON v.id = av.vulnerability_id AND v.user_id = ? AND v.deleted_at IS NULL", userID).
		Where("av.asset_id IN ? AND av.deleted_at IS NULL", assetIDs).
		Group("av.asset_id").
		Scan(&counts).Error
	if err != nil {
		return fmt.Errorf("%w: count asset vulnerabilities: %w", ErrPersistenceFailure, err)
	}

	countByAssetID := make(map[string]int, len(counts))
	for _, count := range counts {
		countByAssetID[count.AssetID] = int(count.Count)
	}
	for index := range assets {
		assets[index].VulnerabilityCount = countByAssetID[assets[index].ID]
	}

	return nil
}

// FindByIDForUser returns a single asset owned by the specified user.
func (r *AssetRepository) FindByIDForUser(ec *appcontext.GinContext, id string, userID string) (model.Asset, error) {
	var asset model.Asset
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Preload("Assessment").
		Where("user_id = ? AND id = ?", userID, id).
		First(&asset).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.Asset{}, ErrRecordNotFound
	}
	if err != nil {
		return model.Asset{}, fmt.Errorf("%w: read asset: %w", ErrPersistenceFailure, err)
	}
	if err := r.loadActiveVulnerabilitiesForAsset(ec, &asset, userID); err != nil {
		return model.Asset{}, err
	}
	assets := []model.Asset{asset}
	if err := r.loadVulnerabilityCounts(ec, assets, userID); err != nil {
		return model.Asset{}, err
	}
	return assets[0], nil
}

// ExistsBySignatureForUser reports whether a user already has an asset with the same normalized signature.
func (r *AssetRepository) ExistsBySignatureForUser(ec *appcontext.GinContext, asset model.Asset, userID string) (bool, error) {
	normalizedName := strings.ToLower(strings.TrimSpace(asset.Name))
	normalizedType := strings.ToLower(strings.TrimSpace(asset.Type))
	normalizedOwner := strings.ToLower(strings.TrimSpace(asset.Owner))
	normalizedCriticality := strings.ToLower(strings.TrimSpace(asset.Criticality))
	if normalizedName == "" || normalizedType == "" || normalizedOwner == "" || normalizedCriticality == "" {
		return false, nil
	}

	normalizedOperatingSystem := strings.ToLower(strings.TrimSpace(optionalAssetString(asset.OperatingSystem)))
	normalizedVendor := strings.ToLower(strings.TrimSpace(optionalAssetString(asset.Vendor)))
	normalizedProduct := strings.ToLower(strings.TrimSpace(optionalAssetString(asset.Product)))
	normalizedVersion := strings.ToLower(strings.TrimSpace(optionalAssetString(asset.Version)))
	normalizedDeviceModel := strings.ToLower(strings.TrimSpace(optionalAssetString(asset.DeviceModel)))

	var count int64
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Model(&model.Asset{}).
		Where(`user_id = ?
			AND LOWER(name) = ?
			AND LOWER(type) = ?
			AND LOWER(owner) = ?
			AND LOWER(criticality) = ?
			AND LOWER(COALESCE(operating_system, '')) = ?
			AND LOWER(COALESCE(vendor, '')) = ?
			AND LOWER(COALESCE(product, '')) = ?
			AND LOWER(COALESCE(version, '')) = ?
			AND LOWER(COALESCE(device_model, '')) = ?`,
			userID,
			normalizedName,
			normalizedType,
			normalizedOwner,
			normalizedCriticality,
			normalizedOperatingSystem,
			normalizedVendor,
			normalizedProduct,
			normalizedVersion,
			normalizedDeviceModel,
		).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%w: check asset uniqueness: %w", ErrPersistenceFailure, err)
	}
	return count > 0, nil
}

// CreateForUser creates a new asset owned by the specified user.
func (r *AssetRepository) CreateForUser(ec *appcontext.GinContext, userID string, asset model.Asset) (model.Asset, error) {
	if userID == "" || asset.Name == "" || asset.Type == "" || asset.Owner == "" || asset.Criticality == "" {
		return model.Asset{}, ErrNotNullViolation
	}
	asset.UserID = userID

	for attempt := 0; attempt < 3; attempt++ {
		identifier, err := commonid.New()
		if err != nil {
			return model.Asset{}, fmt.Errorf("%w: generate asset id: %w", ErrPersistenceFailure, err)
		}
		asset.ID = identifier

		assessment := model.AssetAssessment{
			CPEReviewStatus: model.AssetCPEReviewStatusNeedsReview,
		}

		err = r.dbForContext(ec).WithContext(ec.RequestContext()).Transaction(func(tx *gorm.DB) error {
			if err := createAssetAssessmentWithRandomID(tx, &assessment); err != nil {
				return err
			}

			asset.AssetAssessmentID = &assessment.ID
			if err := tx.Create(&asset).Error; err != nil {
				return err
			}

			asset.Assessment = &assessment
			return nil
		})
		if err == nil {
			return asset, nil
		}

		databaseErr := platformdb.TranslateDatabaseError(err)
		if errors.Is(databaseErr, platformdb.ErrUniqueViolation) && platformdb.IsPrimaryKeyViolation(err) {
			continue
		}
		if errors.Is(databaseErr, platformdb.ErrForeignKeyViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", ErrForeignKeyViolation, databaseErr)
		}
		if errors.Is(databaseErr, platformdb.ErrCheckConstraintViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", ErrCheckConstraintViolation, databaseErr)
		}
		return model.Asset{}, fmt.Errorf("%w: create asset: %w", ErrPersistenceFailure, databaseErr)
	}

	return model.Asset{}, fmt.Errorf("%w: exhausted random id retries", ErrPrimaryKeyViolation)
}

// UpdateForUser updates an asset owned by the specified user.
func (r *AssetRepository) UpdateForUser(ec *appcontext.GinContext, id string, userID string, updates model.Asset) (model.Asset, error) {
	if updates.Name == "" || updates.Type == "" || updates.Owner == "" || updates.Criticality == "" {
		return model.Asset{}, ErrNotNullViolation
	}

	asset, err := r.FindByIDForUser(ec, id, userID)
	if err != nil {
		return model.Asset{}, err
	}

	asset.Name = updates.Name
	asset.Type = updates.Type
	asset.OperatingSystem = updates.OperatingSystem
	asset.Vendor = updates.Vendor
	asset.Product = updates.Product
	asset.Version = updates.Version
	asset.DeviceModel = updates.DeviceModel
	asset.Owner = updates.Owner
	asset.Criticality = updates.Criticality
	setUpdatedBy(ec, &asset.Model)

	result := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Where("id = ? AND user_id = ?", asset.ID, userID).
		Save(&asset)
	err = result.Error
	if err != nil {
		databaseErr := platformdb.TranslateDatabaseError(err)
		if errors.Is(databaseErr, platformdb.ErrForeignKeyViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", ErrForeignKeyViolation, databaseErr)
		}
		if errors.Is(databaseErr, platformdb.ErrCheckConstraintViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", ErrCheckConstraintViolation, databaseErr)
		}
		return model.Asset{}, fmt.Errorf("%w: update asset: %w", ErrPersistenceFailure, databaseErr)
	}
	if result.RowsAffected == 0 {
		return model.Asset{}, ErrRecordNotFound
	}
	return r.FindByIDForUser(ec, id, userID)
}

// DeleteForUser deletes an asset owned by the specified user.
func (r *AssetRepository) DeleteForUser(ec *appcontext.GinContext, id string, userID string) (model.Asset, error) {
	asset, err := r.FindByIDForUser(ec, id, userID)
	if err != nil {
		return model.Asset{}, err
	}

	err = r.dbForContext(ec).WithContext(ec.RequestContext()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.AssetVulnerability{}).
			Where("asset_id = ? AND deleted_at IS NULL", asset.ID).
			Update("deleted_at", gorm.Expr("NOW()")).Error; err != nil {
			return err
		}
		result := tx.Where("id = ? AND user_id = ?", asset.ID, userID).Delete(&model.Asset{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return ErrRecordNotFound
		}
		if asset.AssetAssessmentID != nil {
			if err := tx.Where("id = ?", *asset.AssetAssessmentID).Delete(&model.AssetAssessment{}).Error; err != nil {
				return err
			}
		}
		for _, vulnerability := range asset.Vulnerabilities {
			if err := deleteOrphanedVulnerability(tx, vulnerability); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return model.Asset{}, fmt.Errorf("%w: delete asset: %w", ErrPersistenceFailure, err)
	}
	return asset, nil
}
