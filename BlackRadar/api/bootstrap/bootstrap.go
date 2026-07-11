package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"blackradar/api/config"
	"blackradar/api/model"
)

const (
	bootstrapUsername     = "system_admin"
	bootstrapEmail        = "Test@gmail.com"
	bootstrapPassword     = "Password123!"
	bootstrapOrganization = "admin_home"

	bootstrapUserID          = "77000000-0000-4000-8000-000000000001"
	bootstrapAssetID         = "77000000-0000-4000-8000-000000000002"
	bootstrapVulnerabilityID = "77000000-0000-4000-8000-000000000003"
	bootstrapAssessmentID    = "77000000-0000-4000-8000-000000000004"

	bootstrapAssetName        = "Test Device"
	bootstrapAssetType        = "Device"
	bootstrapAssetOS          = "Linux"
	bootstrapAssetOwner       = "system_admin"
	bootstrapAssetCriticality = "High"

	bootstrapCVEID              = "CVE-2021-44228"
	bootstrapVulnerabilityTitle = "Apache Log4j Remote Code Execution"
	bootstrapSeverity           = "Critical"
	bootstrapStatus             = "Open"
	bootstrapDescription        = "Example NVD-backed CVE used for local testing."
)

// Run seeds developer bootstrap data when enabled.
func Run(ctx context.Context, database *gorm.DB, cfg config.Config) error {
	if !cfg.BootstrapDevData {
		return nil
	}

	if cfg.Environment == "production" {
		return fmt.Errorf("bootstrap dev data cannot run in production")
	}

	if database == nil {
		return fmt.Errorf("missing database for bootstrap")
	}

	return seedDevData(ctx, database)
}

func seedDevData(ctx context.Context, database *gorm.DB) error {
	return database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := clearBootstrapData(ctx, tx); err != nil {
			return err
		}

		organization, err := seedBootstrapOrganization(ctx, tx)
		if err != nil {
			return err
		}

		user, err := seedBootstrapUser(ctx, tx, organization.ID)
		if err != nil {
			return err
		}

		asset, err := seedBootstrapAsset(ctx, tx, organization.ID, user.ID)
		if err != nil {
			return err
		}

		vulnerability, err := seedBootstrapVulnerability(ctx, tx, organization.ID, user.ID)
		if err != nil {
			return err
		}

		return assignBootstrapVulnerability(ctx, tx, asset, vulnerability)
	})
}

func clearBootstrapData(ctx context.Context, database *gorm.DB) error {
	var organization model.Organization
	err := database.WithContext(ctx).
		Where("name = ?", strings.ToLower(strings.TrimSpace(bootstrapOrganization))).
		First(&organization).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return fmt.Errorf("find bootstrap organization for cleanup: %w", err)
	}

	if err := database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(
			`DELETE FROM asset_vulnerabilities
			 WHERE asset_id IN (SELECT id FROM assets WHERE organization_id = ?)
			    OR vulnerability_id IN (SELECT id FROM vulnerabilities WHERE organization_id = ?)`,
			organization.ID, organization.ID,
		).Error; err != nil {
			return fmt.Errorf("delete bootstrap asset vulnerabilities: %w", err)
		}
		if err := tx.Exec(
			`WITH deleted_assets AS (
				DELETE FROM assets
				WHERE organization_id = ?
				RETURNING asset_assessment_id
			)
			DELETE FROM asset_assessments
			WHERE id IN (
				SELECT asset_assessment_id
				FROM deleted_assets
				WHERE asset_assessment_id IS NOT NULL
			)`,
			organization.ID,
		).Error; err != nil {
			return fmt.Errorf("delete bootstrap assets: %w", err)
		}
		if err := tx.Exec(`DELETE FROM vulnerabilities WHERE organization_id = ?`, organization.ID).Error; err != nil {
			return fmt.Errorf("delete bootstrap vulnerabilities: %w", err)
		}
		if err := tx.Exec(`DELETE FROM users WHERE organization_id = ?`, organization.ID).Error; err != nil {
			return fmt.Errorf("delete bootstrap users: %w", err)
		}
		if err := tx.Delete(&organization).Error; err != nil {
			return fmt.Errorf("delete bootstrap organization: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

func seedBootstrapOrganization(ctx context.Context, database *gorm.DB) (model.Organization, error) {
	normalized := strings.ToLower(strings.TrimSpace(bootstrapOrganization))

	var organization model.Organization
	err := database.WithContext(ctx).Where("name = ?", normalized).First(&organization).Error
	if err == nil {
		return organization, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return model.Organization{}, fmt.Errorf("find bootstrap organization: %w", err)
	}

	organization = model.Organization{Name: normalized}
	if err := database.WithContext(ctx).Create(&organization).Error; err != nil {
		return model.Organization{}, fmt.Errorf("create bootstrap organization: %w", err)
	}
	return organization, nil
}

func seedBootstrapUser(ctx context.Context, database *gorm.DB, organizationID string) (model.User, error) {
	email := strings.ToLower(strings.TrimSpace(bootstrapEmail))
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(bootstrapPassword), config.PasswordCost())
	if err != nil {
		return model.User{}, fmt.Errorf("hash bootstrap password: %w", err)
	}

	user := model.User{
		Model:          model.Model{ID: bootstrapUserID},
		OrganizationID: organizationID,
		Username:       bootstrapUsername,
		Email:          email,
		Role:           model.RoleAdmin,
		PasswordHash:   string(passwordHash),
	}
	if err := database.WithContext(ctx).Create(&user).Error; err != nil {
		return model.User{}, fmt.Errorf("create bootstrap user: %w", err)
	}

	return user, nil
}

func seedBootstrapAsset(ctx context.Context, database *gorm.DB, organizationID string, userID string) (model.Asset, error) {
	operatingSystem := bootstrapAssetOS
	assessment := model.AssetAssessment{
		Model:           model.Model{ID: bootstrapAssessmentID},
		CPEReviewStatus: model.AssetCPEReviewStatusNeedsReview,
	}
	asset := model.Asset{
		Model:             model.Model{ID: bootstrapAssetID},
		OrganizationID:    organizationID,
		UserID:            userID,
		AssetAssessmentID: &assessment.ID,
		Name:              bootstrapAssetName,
		Type:              bootstrapAssetType,
		OperatingSystem:   &operatingSystem,
		Owner:             bootstrapAssetOwner,
		Criticality:       bootstrapAssetCriticality,
		RiskLevel:         nil,
	}
	if err := database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&assessment).Error; err != nil {
			return fmt.Errorf("create bootstrap asset assessment: %w", err)
		}
		if err := tx.Create(&asset).Error; err != nil {
			return fmt.Errorf("create bootstrap asset: %w", err)
		}
		return nil
	}); err != nil {
		return model.Asset{}, err
	}

	asset.Assessment = &assessment
	return asset, nil
}

func seedBootstrapVulnerability(ctx context.Context, database *gorm.DB, organizationID string, userID string) (model.Vulnerability, error) {
	vulnerability := model.Vulnerability{
		Model:          model.Model{ID: bootstrapVulnerabilityID},
		OrganizationID: organizationID,
		UserID:         userID,
		CVEID:          bootstrapCVEID,
		Title:          bootstrapVulnerabilityTitle,
		Severity:       bootstrapSeverity,
		Description:    bootstrapDescription,
		Status:         bootstrapStatus,
	}
	if err := database.WithContext(ctx).Create(&vulnerability).Error; err != nil {
		return model.Vulnerability{}, fmt.Errorf("create bootstrap vulnerability: %w", err)
	}

	return vulnerability, nil
}

func assignBootstrapVulnerability(ctx context.Context, database *gorm.DB, asset model.Asset, vulnerability model.Vulnerability) error {
	var assignmentCount int64
	err := database.WithContext(ctx).
		Table("asset_vulnerabilities").
		Where("asset_id = ? AND vulnerability_id = ? AND deleted_at IS NULL", asset.ID, vulnerability.ID).
		Count(&assignmentCount).Error
	if err != nil {
		return fmt.Errorf("check bootstrap assignment: %w", err)
	}

	if assignmentCount > 0 {
		return nil
	}

	if err := database.WithContext(ctx).Model(&asset).Association("Vulnerabilities").Append(&vulnerability); err != nil {
		return fmt.Errorf("assign bootstrap vulnerability: %w", err)
	}

	return nil
}
