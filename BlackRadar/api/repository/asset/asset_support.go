package repository

import (
	"errors"
	"fmt"

	commonid "blackradar/api/common/id"
	"blackradar/api/model"
	platformdb "blackradar/api/platform/db"
	appcontext "blackradar/api/platform/requestcontext"

	"gorm.io/gorm"
)

// dbForContext returns the request-scoped database when present, otherwise the repository database.
func (r *AssetRepository) dbForContext(ec *appcontext.GinContext) *gorm.DB {
	if ec != nil && ec.Database() != nil {
		return ec.Database()
	}
	return r.db
}

// loadActiveVulnerabilitiesForAsset loads active vulnerability assignments for an asset.
func (r *AssetRepository) loadActiveVulnerabilitiesForAsset(ec *appcontext.GinContext, asset *model.Asset, userID string) error {
	var vulnerabilities []model.Vulnerability
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Model(&model.Vulnerability{}).
		Joins("JOIN asset_vulnerabilities av ON av.vulnerability_id = vulnerabilities.id AND av.deleted_at IS NULL").
		Where("av.asset_id = ? AND vulnerabilities.user_id = ?", asset.ID, userID).
		Order("vulnerabilities.id").
		Find(&vulnerabilities).Error
	if err != nil {
		return fmt.Errorf("%w: load asset vulnerabilities: %w", ErrPersistenceFailure, err)
	}
	asset.Vulnerabilities = vulnerabilities
	return nil
}

// createAssetAssessmentWithRandomID persists an asset assessment with a random public identifier.
func createAssetAssessmentWithRandomID(tx *gorm.DB, assessment *model.AssetAssessment) error {
	for attempt := 0; attempt < 3; attempt++ {
		identifier, err := commonid.New()
		if err != nil {
			return err
		}
		assessment.ID = identifier

		err = tx.Create(assessment).Error
		if err == nil {
			return nil
		}

		databaseErr := platformdb.TranslateDatabaseError(err)
		if errors.Is(databaseErr, platformdb.ErrUniqueViolation) && platformdb.IsPrimaryKeyViolation(err) {
			continue
		}
		return err
	}

	return fmt.Errorf("exhausted random id retries for asset assessment")
}

// deleteOrphanedVulnerability removes a vulnerability when no assets still reference it.
func deleteOrphanedVulnerability(tx *gorm.DB, vulnerability model.Vulnerability) error {
	var count int64
	if err := tx.Model(&model.AssetVulnerability{}).
		Where("vulnerability_id = ? AND deleted_at IS NULL", vulnerability.ID).
		Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	return tx.Delete(&vulnerability).Error
}

// setUpdatedBy records the authenticated user as the last updater when available.
func setUpdatedBy(ec *appcontext.GinContext, target *model.Model) {
	if ec == nil || target == nil {
		return
	}

	userID, err := ec.UserID()
	if err != nil {
		return
	}

	target.UpdatedByID = &userID
}

// optionalAssetString returns the pointed string value or an empty string.
func optionalAssetString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
