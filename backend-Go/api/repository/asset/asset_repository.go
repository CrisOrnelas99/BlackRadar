// Package repository provides asset persistence operations.
package repository

import (
	"errors"
	"fmt"

	"gorm.io/gorm"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/model"
	baserepository "secureops/backend-go/api/repository"
	"secureops/backend-go/api/utils"
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
func (r *AssetRepository) FindAllByOrganization(ec *appcontext.GinContext, organizationID int64) ([]model.Asset, error) {
	var assets []model.Asset
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Where("organization_id = ?", organizationID).Order("id").Find(&assets).Error
	if err != nil {
		return nil, fmt.Errorf("%w: %w", baserepository.ErrReadFailed, err)
	}
	return assets, nil
}

// FindByIDForOrganization returns a single asset owned by the specified organization.
func (r *AssetRepository) FindByIDForOrganization(ec *appcontext.GinContext, id int64, organizationID int64) (model.Asset, error) {
	var asset model.Asset
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Preload("Vulnerabilities", "organization_id = ?", organizationID).
		Where("organization_id = ?", organizationID).
		First(&asset, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.Asset{}, baserepository.ErrAssetNotFound
	}
	if err != nil {
		return model.Asset{}, fmt.Errorf("%w: %w", baserepository.ErrReadFailed, err)
	}
	return asset, nil
}

// Save creates a new asset record.
func (r *AssetRepository) Save(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error) {
	if asset.OrganizationID <= 0 || asset.UserID <= 0 || asset.Name == "" || asset.Type == "" || asset.Owner == "" || asset.Criticality == "" {
		return model.Asset{}, baserepository.ErrInvalidData
	}

	for attempt := 0; attempt < 3; attempt++ {
		if asset.ID == 0 || attempt > 0 {
			asset.ID = utils.NewRandomID()
		}

		err := r.dbForContext(ec).WithContext(ec.RequestContext()).Create(&asset).Error
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
func (r *AssetRepository) UpdateForOrganization(ec *appcontext.GinContext, id int64, organizationID int64, updates model.Asset) (model.Asset, error) {
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
func (r *AssetRepository) UpdateMatchAnalysisForOrganization(ec *appcontext.GinContext, id int64, organizationID int64, analysis baserepository.AssetMatchUpdate) (model.Asset, error) {
	if analysis.CPEReviewStatus == "" {
		return model.Asset{}, baserepository.ErrInvalidData
	}

	asset, err := r.FindByIDForOrganization(ec, id, organizationID)
	if err != nil {
		return model.Asset{}, err
	}

	asset.ProductFingerprint = analysis.ProductFingerprint
	asset.SelectedCPE = analysis.SelectedCPE
	asset.CPEConfidence = analysis.CPEConfidence
	asset.CPEReviewStatus = analysis.CPEReviewStatus
	asset.CPEReviewNotes = analysis.CPEReviewNotes
	asset.CPECandidateCount = analysis.CPECandidateCount
	asset.CPEMatchedAt = analysis.CPEMatchedAt

	err = r.dbForContext(ec).WithContext(ec.RequestContext()).Save(&asset).Error
	if err != nil {
		databaseErr := utils.TranslateDatabaseError(err)
		if errors.Is(databaseErr, utils.ErrCheckConstraintViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", baserepository.ErrInvalidData, databaseErr)
		}
		return model.Asset{}, fmt.Errorf("%w: %w", baserepository.ErrUpdateFailed, databaseErr)
	}

	return r.FindByIDForOrganization(ec, id, organizationID)
}

// DeleteForOrganization deletes an asset owned by the specified organization.
func (r *AssetRepository) DeleteForOrganization(ec *appcontext.GinContext, id int64, organizationID int64) (model.Asset, error) {
	asset, err := r.FindByIDForOrganization(ec, id, organizationID)
	if err != nil {
		return model.Asset{}, err
	}

	err = r.dbForContext(ec).WithContext(ec.RequestContext()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("DELETE FROM asset_vulnerabilities WHERE asset_id = ?", asset.ID).Error; err != nil {
			return err
		}
		if err := tx.Delete(&asset).Error; err != nil {
			return err
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
func (r *AssetRepository) AssignVulnerabilityForOrganization(ec *appcontext.GinContext, assetID int64, organizationID int64, vulnerabilityID int64) (model.Asset, error) {
	asset, vulnerability, err := r.findAssetAndVulnerabilityForOrganization(ec, assetID, organizationID, vulnerabilityID)
	if err != nil {
		return model.Asset{}, err
	}

	for _, assigned := range asset.Vulnerabilities {
		if assigned.ID == vulnerability.ID {
			return model.Asset{}, baserepository.ErrDuplicateAssignment
		}
	}

	err = r.dbForContext(ec).WithContext(ec.RequestContext()).Model(&asset).Association("Vulnerabilities").Append(&vulnerability)
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
func (r *AssetRepository) RemoveVulnerabilityForOrganization(ec *appcontext.GinContext, assetID int64, organizationID int64, vulnerabilityID int64) (model.Asset, error) {
	asset, vulnerability, err := r.findAssetAndVulnerabilityForOrganization(ec, assetID, organizationID, vulnerabilityID)
	if err != nil {
		return model.Asset{}, err
	}

	err = r.dbForContext(ec).WithContext(ec.RequestContext()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&asset).Association("Vulnerabilities").Delete(&vulnerability); err != nil {
			return err
		}
		return deleteOrphanedVulnerability(tx, vulnerability)
	})
	if err != nil {
		return model.Asset{}, fmt.Errorf("%w: %w", baserepository.ErrDeleteFailed, err)
	}

	return r.FindByIDForOrganization(ec, assetID, organizationID)
}

// findAssetAndVulnerabilityForOrganization loads the asset and vulnerability for the specified organization.
func (r *AssetRepository) findAssetAndVulnerabilityForOrganization(ec *appcontext.GinContext, assetID int64, organizationID int64, vulnerabilityID int64) (model.Asset, model.Vulnerability, error) {
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

// deleteOrphanedVulnerability removes a vulnerability when no assets still reference it.
func deleteOrphanedVulnerability(tx *gorm.DB, vulnerability model.Vulnerability) error {
	var count int64
	if err := tx.Table("asset_vulnerabilities").Where("vulnerability_id = ?", vulnerability.ID).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	return tx.Delete(&vulnerability).Error
}
