// Package repository provides asset persistence operations.
package repository

import (
	"errors"
	"fmt"
	"strings"
	"time"

	commonid "blackradar/api/common/id"
	commonrisk "blackradar/api/common/risk"
	"blackradar/api/model"
	platformdb "blackradar/api/platform/db"
	appcontext "blackradar/api/platform/requestcontext"
	authrepo "blackradar/api/repository/authorization"

	"gorm.io/gorm"
)

// AssetRepository persists asset records.
type AssetRepository struct {
	db *gorm.DB
}

// AssetMatchUpdate carries the backend-generated CPE match state for an asset.
type AssetMatchUpdate struct {
	ProductFingerprint *string
	SelectedCPE        *string
	CPEConfidence      *float64
	CPEReviewStatus    string
	CPEReviewNotes     *string
	CPECandidateCount  int
	CPEMatchedAt       *time.Time
}

// NewAssetRepository creates an asset repository backed by the supplied database.
func NewAssetRepository(db *gorm.DB) *AssetRepository {
	return &AssetRepository{db: db}
}

// dbForContext returns the request-scoped database when present, otherwise the repository database.
func (r *AssetRepository) dbForContext(ec *appcontext.GinContext) *gorm.DB {
	if ec != nil && ec.Database() != nil {
		return ec.Database()
	}
	return r.db
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
	return assets, nil
}

// FindByIDForUser returns a single asset owned by the specified user.
func (r *AssetRepository) FindByIDForUser(ec *appcontext.GinContext, id string, userID string) (model.Asset, error) {
	var asset model.Asset
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Preload("Assessment").
		Where("user_id = ?", userID).
		First(&asset, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.Asset{}, ErrAssetNotFound
	}
	if err != nil {
		return model.Asset{}, fmt.Errorf("%w: read asset: %w", ErrPersistenceFailure, err)
	}
	if err := r.loadActiveVulnerabilitiesForAsset(ec, &asset, userID); err != nil {
		return model.Asset{}, err
	}
	return asset, nil
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

// Save creates a new asset record.
func (r *AssetRepository) Save(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error) {
	if asset.UserID == "" || asset.Name == "" || asset.Type == "" || asset.Owner == "" || asset.Criticality == "" {
		return model.Asset{}, ErrInvalidData
	}

	for attempt := 0; attempt < 3; attempt++ {
		if asset.ID == "" || attempt > 0 {
			identifier, err := commonid.New()
			if err != nil {
				return model.Asset{}, fmt.Errorf("%w: generate asset id: %w", ErrPersistenceFailure, err)
			}
			asset.ID = identifier
		}

		assessment := model.AssetAssessment{
			CPEReviewStatus: model.AssetCPEReviewStatusNeedsReview,
		}

		err := r.dbForContext(ec).WithContext(ec.RequestContext()).Transaction(func(tx *gorm.DB) error {
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
			return model.Asset{}, fmt.Errorf("%w: %w", ErrInvalidReference, databaseErr)
		}
		if errors.Is(databaseErr, platformdb.ErrCheckConstraintViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", ErrInvalidData, databaseErr)
		}
		return model.Asset{}, fmt.Errorf("%w: create asset: %w", ErrPersistenceFailure, databaseErr)
	}

	return model.Asset{}, fmt.Errorf("%w: exhausted random id retries", ErrPrimaryKeyConflict)
}

// UpdateForUser updates an asset owned by the specified user.
func (r *AssetRepository) UpdateForUser(ec *appcontext.GinContext, id string, userID string, updates model.Asset) (model.Asset, error) {
	if updates.Name == "" || updates.Type == "" || updates.Owner == "" || updates.Criticality == "" {
		return model.Asset{}, ErrInvalidData
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

	err = r.dbForContext(ec).WithContext(ec.RequestContext()).Save(&asset).Error
	if err != nil {
		databaseErr := platformdb.TranslateDatabaseError(err)
		if errors.Is(databaseErr, platformdb.ErrForeignKeyViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", ErrInvalidReference, databaseErr)
		}
		if errors.Is(databaseErr, platformdb.ErrCheckConstraintViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", ErrInvalidData, databaseErr)
		}
		return model.Asset{}, fmt.Errorf("%w: update asset: %w", ErrPersistenceFailure, databaseErr)
	}
	return r.FindByIDForUser(ec, id, userID)
}

// UpdateMatchAnalysisForUser stores backend-generated CPE match state for an asset.
func (r *AssetRepository) UpdateMatchAnalysisForUser(ec *appcontext.GinContext, id string, userID string, analysis any) (model.Asset, error) {
	analysisUpdate, ok := analysis.(AssetMatchUpdate)
	if !ok {
		return model.Asset{}, ErrInvalidData
	}
	if analysisUpdate.CPEReviewStatus == "" {
		return model.Asset{}, ErrInvalidData
	}

	asset, err := r.FindByIDForUser(ec, id, userID)
	if err != nil {
		return model.Asset{}, err
	}

	err = r.dbForContext(ec).WithContext(ec.RequestContext()).Transaction(func(tx *gorm.DB) error {
		assessment := model.AssetAssessment{}
		if asset.Assessment != nil {
			assessment = *asset.Assessment
		}

		assessment.ProductFingerprint = analysisUpdate.ProductFingerprint
		assessment.SelectedCPE = analysisUpdate.SelectedCPE
		assessment.CPEConfidence = analysisUpdate.CPEConfidence
		assessment.CPEReviewStatus = analysisUpdate.CPEReviewStatus
		assessment.CPEReviewNotes = analysisUpdate.CPEReviewNotes
		assessment.CPECandidateCount = analysisUpdate.CPECandidateCount
		assessment.CPEMatchedAt = analysisUpdate.CPEMatchedAt
		setUpdatedBy(ec, &assessment.Model)

		if asset.AssetAssessmentID == nil {
			if err := createAssetAssessmentWithRandomID(tx, &assessment); err != nil {
				return err
			}
			asset.AssetAssessmentID = &assessment.ID
			if err := tx.Model(&asset).Update("asset_assessment_id", assessment.ID).Error; err != nil {
				return err
			}
			return nil
		}

		assessment.ID = *asset.AssetAssessmentID
		return tx.Save(&assessment).Error
	})
	if err != nil {
		databaseErr := platformdb.TranslateDatabaseError(err)
		if errors.Is(databaseErr, platformdb.ErrCheckConstraintViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", ErrInvalidData, databaseErr)
		}
		if errors.Is(databaseErr, platformdb.ErrForeignKeyViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", ErrInvalidReference, databaseErr)
		}
		return model.Asset{}, fmt.Errorf("%w: update asset match analysis: %w", ErrPersistenceFailure, databaseErr)
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
		if err := tx.Delete(&asset).Error; err != nil {
			return err
		}
		if asset.AssetAssessmentID != nil {
			if err := tx.Delete(&model.AssetAssessment{}, *asset.AssetAssessmentID).Error; err != nil {
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

// AssignVulnerabilityForUser associates a vulnerability with an asset owned by the specified user.
func (r *AssetRepository) AssignVulnerabilityForUser(ec *appcontext.GinContext, assetID string, userID string, vulnerabilityID string) (model.Asset, error) {
	if err := authrepo.RequireAdminFromDatabase(ec, r.dbForContext(ec)); err != nil {
		return model.Asset{}, err
	}

	asset, vulnerability, err := r.findAssetAndVulnerabilityForUser(ec, assetID, userID, vulnerabilityID)
	if err != nil {
		return model.Asset{}, err
	}

	for _, assigned := range asset.Vulnerabilities {
		if assigned.ID == vulnerability.ID {
			return model.Asset{}, ErrDuplicateAssignment
		}
	}

	err = r.dbForContext(ec).WithContext(ec.RequestContext()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&asset).Association("Vulnerabilities").Append(&vulnerability); err != nil {
			return err
		}
		return RefreshAssetRisk(tx, assetID, userID)
	})
	if err != nil {
		databaseErr := platformdb.TranslateDatabaseError(err)
		if errors.Is(databaseErr, platformdb.ErrUniqueViolation) {
			return model.Asset{}, ErrDuplicateAssignment
		}
		if errors.Is(databaseErr, platformdb.ErrForeignKeyViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", ErrInvalidReference, databaseErr)
		}
		return model.Asset{}, fmt.Errorf("%w: assign vulnerability: %w", ErrPersistenceFailure, databaseErr)
	}

	return r.FindByIDForUser(ec, assetID, userID)
}

// RemoveVulnerabilityForUser removes a vulnerability from an asset owned by the specified user.
func (r *AssetRepository) RemoveVulnerabilityForUser(ec *appcontext.GinContext, assetID string, userID string, vulnerabilityID string) (model.Asset, error) {
	if err := authrepo.RequireAdminFromDatabase(ec, r.dbForContext(ec)); err != nil {
		return model.Asset{}, err
	}

	asset, vulnerability, err := r.findAssetAndVulnerabilityForUser(ec, assetID, userID, vulnerabilityID)
	if err != nil {
		return model.Asset{}, err
	}

	err = r.dbForContext(ec).WithContext(ec.RequestContext()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.AssetVulnerability{}).
			Where("asset_id = ? AND vulnerability_id = ? AND deleted_at IS NULL", asset.ID, vulnerability.ID).
			Update("deleted_at", gorm.Expr("NOW()")).Error; err != nil {
			return err
		}
		if err := deleteOrphanedVulnerability(tx, vulnerability); err != nil {
			return err
		}
		return RefreshAssetRisk(tx, assetID, userID)
	})
	if err != nil {
		return model.Asset{}, fmt.Errorf("%w: remove vulnerability: %w", ErrPersistenceFailure, err)
	}
	return r.FindByIDForUser(ec, assetID, userID)
}

// findAssetAndVulnerabilityForUser loads the asset and vulnerability for the specified user.
func (r *AssetRepository) findAssetAndVulnerabilityForUser(ec *appcontext.GinContext, assetID string, userID string, vulnerabilityID string) (model.Asset, model.Vulnerability, error) {
	asset, err := r.FindByIDForUser(ec, assetID, userID)
	if err != nil {
		return model.Asset{}, model.Vulnerability{}, err
	}

	var vulnerability model.Vulnerability
	err = r.dbForContext(ec).WithContext(ec.RequestContext()).
		Where("user_id = ?", userID).
		First(&vulnerability, vulnerabilityID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.Asset{}, model.Vulnerability{}, ErrVulnerabilityNotFound
	}
	if err != nil {
		return model.Asset{}, model.Vulnerability{}, fmt.Errorf("%w: read vulnerability: %w", ErrPersistenceFailure, err)
	}

	return asset, vulnerability, nil
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

// createAssetAssessmentWithRandomID persists an asset assessment with a random public identifier.
func createAssetAssessmentWithRandomID(tx *gorm.DB, assessment *model.AssetAssessment) error {
	for attempt := 0; attempt < 3; attempt++ {
		if err := assignRandomAssetAssessmentID(assessment); err != nil {
			return err
		}

		err := tx.Create(assessment).Error
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

// assignRandomAssetAssessmentID sets a non-zero arbitrary public identifier on the assessment.
func assignRandomAssetAssessmentID(assessment *model.AssetAssessment) error {
	identifier, err := commonid.New()
	if err != nil {
		return err
	}

	assessment.ID = identifier
	return nil
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

// RefreshAssetRisk recalculates and persists the risk level for a single asset.
func RefreshAssetRisk(tx *gorm.DB, assetID string, userID string) error {
	var asset model.Asset
	if err := tx.Where("user_id = ?", userID).
		First(&asset, assetID).Error; err != nil {
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
		Update("risk_level", commonrisk.PointerFromVulnerabilities(vulnerabilities)).Error
}
