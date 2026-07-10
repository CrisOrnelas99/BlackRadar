// Package repository provides asset persistence operations.
package repository

import (
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	appcontext "blackradar/api/context"
	"blackradar/api/model"
	baserepository "blackradar/api/repository"
	"blackradar/api/utils"
)

// AssetRepository persists asset records.
type AssetRepository struct {
	db *gorm.DB
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

// FindAllByOrganization returns all assets owned by the specified organization.
func (r *AssetRepository) FindAllByOrganization(ec *appcontext.GinContext, organizationID string) ([]model.Asset, error) {
	var assets []model.Asset
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Preload("Assessment").
		Where("organization_id = ?", organizationID).
		Order("id").
		Find(&assets).Error
	if err != nil {
		return nil, fmt.Errorf("%w: %w", baserepository.ErrReadFailed, err)
	}
	return assets, nil
}

// FindByIDForOrganization returns a single asset owned by the specified organization.
func (r *AssetRepository) FindByIDForOrganization(ec *appcontext.GinContext, id string, organizationID string) (model.Asset, error) {
	var asset model.Asset
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Preload("Assessment").
		Where("organization_id = ?", organizationID).
		First(&asset, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.Asset{}, baserepository.ErrAssetNotFound
	}
	if err != nil {
		return model.Asset{}, fmt.Errorf("%w: %w", baserepository.ErrReadFailed, err)
	}
	if err := r.loadActiveVulnerabilitiesForAsset(ec, &asset, organizationID); err != nil {
		return model.Asset{}, err
	}
	return asset, nil
}

// ExistsBySignatureForOrganization reports whether a tenant already has an asset with the same normalized signature.
func (r *AssetRepository) ExistsBySignatureForOrganization(ec *appcontext.GinContext, asset model.Asset, organizationID string) (bool, error) {
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
		Where(`organization_id = ?
			AND LOWER(name) = ?
			AND LOWER(type) = ?
			AND LOWER(owner) = ?
			AND LOWER(criticality) = ?
			AND LOWER(COALESCE(operating_system, '')) = ?
			AND LOWER(COALESCE(vendor, '')) = ?
			AND LOWER(COALESCE(product, '')) = ?
			AND LOWER(COALESCE(version, '')) = ?
			AND LOWER(COALESCE(device_model, '')) = ?`,
			organizationID,
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
		return false, fmt.Errorf("%w: %w", baserepository.ErrReadFailed, err)
	}
	return count > 0, nil
}

// Save creates a new asset record.
func (r *AssetRepository) Save(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error) {
	if asset.OrganizationID == "" || asset.UserID == "" || asset.Name == "" || asset.Type == "" || asset.Owner == "" || asset.Criticality == "" {
		return model.Asset{}, baserepository.ErrInvalidData
	}

	for attempt := 0; attempt < 3; attempt++ {
		if asset.ID == "" || attempt > 0 {
			asset.ID = utils.NewRandomID()
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

		databaseErr := utils.TranslateDatabaseError(err)
		if errors.Is(databaseErr, utils.ErrUniqueViolation) && utils.IsPrimaryKeyViolation(err) {
			continue
		}
		if errors.Is(databaseErr, utils.ErrForeignKeyViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", baserepository.ErrInvalidReference, databaseErr)
		}
		if errors.Is(databaseErr, utils.ErrCheckConstraintViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", baserepository.ErrInvalidData, databaseErr)
		}
		return model.Asset{}, fmt.Errorf("%w: %w", baserepository.ErrCreateFailed, databaseErr)
	}

	return model.Asset{}, fmt.Errorf("%w: exhausted random id retries", baserepository.ErrCreateFailed)
}

// UpdateForOrganization updates an asset owned by the specified organization.
func (r *AssetRepository) UpdateForOrganization(ec *appcontext.GinContext, id string, organizationID string, updates model.Asset) (model.Asset, error) {
	if updates.Name == "" || updates.Type == "" || updates.Owner == "" || updates.Criticality == "" {
		return model.Asset{}, baserepository.ErrInvalidData
	}

	asset, err := r.FindByIDForOrganization(ec, id, organizationID)
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
		databaseErr := utils.TranslateDatabaseError(err)
		if errors.Is(databaseErr, utils.ErrForeignKeyViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", baserepository.ErrInvalidReference, databaseErr)
		}
		if errors.Is(databaseErr, utils.ErrCheckConstraintViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", baserepository.ErrInvalidData, databaseErr)
		}
		return model.Asset{}, fmt.Errorf("%w: %w", baserepository.ErrUpdateFailed, databaseErr)
	}
	return r.FindByIDForOrganization(ec, id, organizationID)
}

// UpdateMatchAnalysisForOrganization stores backend-generated CPE match state for an asset.
func (r *AssetRepository) UpdateMatchAnalysisForOrganization(ec *appcontext.GinContext, id string, organizationID string, analysis baserepository.AssetMatchUpdate) (model.Asset, error) {
	if analysis.CPEReviewStatus == "" {
		return model.Asset{}, baserepository.ErrInvalidData
	}

	asset, err := r.FindByIDForOrganization(ec, id, organizationID)
	if err != nil {
		return model.Asset{}, err
	}

	err = r.dbForContext(ec).WithContext(ec.RequestContext()).Transaction(func(tx *gorm.DB) error {
		assessment := model.AssetAssessment{}
		if asset.Assessment != nil {
			assessment = *asset.Assessment
		}

		assessment.ProductFingerprint = analysis.ProductFingerprint
		assessment.SelectedCPE = analysis.SelectedCPE
		assessment.CPEConfidence = analysis.CPEConfidence
		assessment.CPEReviewStatus = analysis.CPEReviewStatus
		assessment.CPEReviewNotes = analysis.CPEReviewNotes
		assessment.CPECandidateCount = analysis.CPECandidateCount
		assessment.CPEMatchedAt = analysis.CPEMatchedAt
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
		databaseErr := utils.TranslateDatabaseError(err)
		if errors.Is(databaseErr, utils.ErrCheckConstraintViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", baserepository.ErrInvalidData, databaseErr)
		}
		if errors.Is(databaseErr, utils.ErrForeignKeyViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", baserepository.ErrInvalidReference, databaseErr)
		}
		return model.Asset{}, fmt.Errorf("%w: %w", baserepository.ErrUpdateFailed, databaseErr)
	}

	return r.FindByIDForOrganization(ec, id, organizationID)
}

// DeleteForOrganization deletes an asset owned by the specified organization.
func (r *AssetRepository) DeleteForOrganization(ec *appcontext.GinContext, id string, organizationID string) (model.Asset, error) {
	asset, err := r.FindByIDForOrganization(ec, id, organizationID)
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
		return model.Asset{}, fmt.Errorf("%w: %w", baserepository.ErrDeleteFailed, err)
	}
	return asset, nil
}

// AssignVulnerabilityForOrganization associates a vulnerability with an asset owned by the specified organization.
func (r *AssetRepository) AssignVulnerabilityForOrganization(ec *appcontext.GinContext, assetID string, organizationID string, vulnerabilityID string) (model.Asset, error) {
	if err := baserepository.RequireAdminFromDatabase(ec, r.dbForContext(ec)); err != nil {
		return model.Asset{}, err
	}

	asset, vulnerability, err := r.findAssetAndVulnerabilityForOrganization(ec, assetID, organizationID, vulnerabilityID)
	if err != nil {
		return model.Asset{}, err
	}

	for _, assigned := range asset.Vulnerabilities {
		if assigned.ID == vulnerability.ID {
			return model.Asset{}, baserepository.ErrDuplicateAssignment
		}
	}

	err = r.dbForContext(ec).WithContext(ec.RequestContext()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&asset).Association("Vulnerabilities").Append(&vulnerability); err != nil {
			return err
		}
		return baserepository.RefreshAssetRiskLevel(tx, assetID, organizationID)
	})
	if err != nil {
		databaseErr := utils.TranslateDatabaseError(err)
		if errors.Is(databaseErr, utils.ErrUniqueViolation) {
			return model.Asset{}, baserepository.ErrDuplicateAssignment
		}
		if errors.Is(databaseErr, utils.ErrForeignKeyViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", baserepository.ErrInvalidReference, databaseErr)
		}
		return model.Asset{}, fmt.Errorf("%w: %w", baserepository.ErrCreateFailed, databaseErr)
	}

	return r.FindByIDForOrganization(ec, assetID, organizationID)
}

// RemoveVulnerabilityForOrganization removes a vulnerability from an asset owned by the specified organization.
func (r *AssetRepository) RemoveVulnerabilityForOrganization(ec *appcontext.GinContext, assetID string, organizationID string, vulnerabilityID string) (model.Asset, error) {
	if err := baserepository.RequireAdminFromDatabase(ec, r.dbForContext(ec)); err != nil {
		return model.Asset{}, err
	}

	asset, vulnerability, err := r.findAssetAndVulnerabilityForOrganization(ec, assetID, organizationID, vulnerabilityID)
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
		return baserepository.RefreshAssetRiskLevel(tx, assetID, organizationID)
	})
	if err != nil {
		return model.Asset{}, fmt.Errorf("%w: %w", baserepository.ErrDeleteFailed, err)
	}
	return r.FindByIDForOrganization(ec, assetID, organizationID)
}

// findAssetAndVulnerabilityForOrganization loads the asset and vulnerability for the specified organization.
func (r *AssetRepository) findAssetAndVulnerabilityForOrganization(ec *appcontext.GinContext, assetID string, organizationID string, vulnerabilityID string) (model.Asset, model.Vulnerability, error) {
	asset, err := r.FindByIDForOrganization(ec, assetID, organizationID)
	if err != nil {
		return model.Asset{}, model.Vulnerability{}, err
	}

	var vulnerability model.Vulnerability
	err = r.dbForContext(ec).WithContext(ec.RequestContext()).
		Where("organization_id = ?", organizationID).
		First(&vulnerability, vulnerabilityID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.Asset{}, model.Vulnerability{}, baserepository.ErrVulnerabilityNotFound
	}
	if err != nil {
		return model.Asset{}, model.Vulnerability{}, fmt.Errorf("%w: %w", baserepository.ErrReadFailed, err)
	}

	return asset, vulnerability, nil
}

func (r *AssetRepository) loadActiveVulnerabilitiesForAsset(ec *appcontext.GinContext, asset *model.Asset, organizationID string) error {
	var vulnerabilities []model.Vulnerability
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Model(&model.Vulnerability{}).
		Joins("JOIN asset_vulnerabilities av ON av.vulnerability_id = vulnerabilities.id AND av.deleted_at IS NULL").
		Where("av.asset_id = ? AND vulnerabilities.organization_id = ?", asset.ID, organizationID).
		Order("vulnerabilities.id").
		Find(&vulnerabilities).Error
	if err != nil {
		return fmt.Errorf("%w: %w", baserepository.ErrReadFailed, err)
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
		assignRandomAssetAssessmentID(assessment)
		err := tx.Create(assessment).Error
		if err == nil {
			return nil
		}

		databaseErr := utils.TranslateDatabaseError(err)
		if errors.Is(databaseErr, utils.ErrUniqueViolation) && utils.IsPrimaryKeyViolation(err) {
			continue
		}
		return err
	}

	return fmt.Errorf("exhausted random id retries for asset assessment")
}

// assignRandomAssetAssessmentID sets a non-zero arbitrary public identifier on the assessment.
func assignRandomAssetAssessmentID(assessment *model.AssetAssessment) {
	assessment.ID = utils.NewRandomID()
}

func setUpdatedBy(ec *appcontext.GinContext, target *model.Model) {
	if ec == nil || target == nil || ec.UserID() == "" {
		return
	}
	userID := ec.UserID()
	target.UpdatedByID = &userID
}

func optionalAssetString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
