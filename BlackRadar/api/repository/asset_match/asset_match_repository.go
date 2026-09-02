// Package repository provides asset match persistence operations.
package repository

import (
	"errors"
	"fmt"
	"time"

	"blackradar/api/model"
	platformdb "blackradar/api/platform/db"
	appcontext "blackradar/api/platform/requestcontext"

	"gorm.io/gorm"
)

// AssetMatchRepository persists asset match records.
type AssetMatchRepository struct {
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

// NewAssetMatchRepository creates an asset match repository backed by the supplied database.
func NewAssetMatchRepository(db *gorm.DB) *AssetMatchRepository {
	return &AssetMatchRepository{db: db}
}

// FindByIDForUser returns an asset in the specified user's organization.
func (r *AssetMatchRepository) FindByIDForUser(ec *appcontext.GinContext, id string, userID string) (model.Asset, error) {
	var asset model.Asset
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Preload("Assessment").
		Where("organization_id = (SELECT organization_id FROM users WHERE id = ?) AND id = ?", userID, id).
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
	return asset, nil
}

// UpdateMatchAnalysisForUser stores backend-generated CPE match state for an asset.
func (r *AssetMatchRepository) UpdateMatchAnalysisForUser(ec *appcontext.GinContext, id string, userID string, analysis AssetMatchUpdate) (model.Asset, error) {
	if analysis.CPEReviewStatus == "" {
		return model.Asset{}, ErrNotNullViolation
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
		databaseErr := platformdb.TranslateDatabaseError(err)
		if errors.Is(databaseErr, platformdb.ErrCheckConstraintViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", ErrCheckConstraintViolation, databaseErr)
		}
		if errors.Is(databaseErr, platformdb.ErrForeignKeyViolation) {
			return model.Asset{}, fmt.Errorf("%w: %w", ErrForeignKeyViolation, databaseErr)
		}
		return model.Asset{}, fmt.Errorf("%w: update asset match analysis: %w", ErrPersistenceFailure, databaseErr)
	}

	return r.FindByIDForUser(ec, id, userID)
}
