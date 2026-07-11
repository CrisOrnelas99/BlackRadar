// Package bootstrap seeds local development data at application startup when enabled.
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
	bootstrapOrganizationID = "77000000-0000-4000-8000-000000000000"
	bootstrapUserID         = "77000000-0000-4000-8000-000000000001"
	bootstrapAssetID        = "77000000-0000-4000-8000-000000000002"

	bootstrapVulnerabilityID = "77000000-0000-4000-8000-000000000003"
	bootstrapAssessmentID    = "77000000-0000-4000-8000-000000000004"

	bootstrapUsername     = "system_admin"
	bootstrapEmail        = "system_admin@example.invalid"
	bootstrapOrganization = "admin_home"

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

// Run seeds developer bootstrap data when explicitly enabled.
func Run(ctx context.Context, database *gorm.DB, cfg config.Config) error {
	if !cfg.BootstrapDevData {
		return nil
	}

	if !cfg.AllowsBootstrapData() {
		return fmt.Errorf(
			"%w: %q",
			config.ErrBootstrapNotAllowed,
			cfg.Environment,
		)
	}

	if strings.TrimSpace(cfg.BootstrapDevPassword) == "" {
		return fmt.Errorf("%w", config.ErrMissingBootstrapPassword)
	}

	if database == nil {
		return fmt.Errorf("%w", ErrDatabaseRequired)
	}

	return seedDevData(ctx, database, cfg.BootstrapDevPassword)
}

// seedDevData recreates the known bootstrap records inside one transaction.
func seedDevData(
	ctx context.Context,
	database *gorm.DB,
	password string,
) error {
	return database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := validateExistingBootstrapOrganization(tx); err != nil {
			return err
		}

		if err := clearBootstrapData(tx); err != nil {
			return err
		}

		organization, err := seedBootstrapOrganization(tx)
		if err != nil {
			return err
		}

		user, err := seedBootstrapUser(
			tx,
			organization.ID,
			password,
		)
		if err != nil {
			return err
		}

		asset, err := seedBootstrapAsset(
			tx,
			organization.ID,
			user.ID,
		)
		if err != nil {
			return err
		}

		vulnerability, err := seedBootstrapVulnerability(
			tx,
			organization.ID,
			user.ID,
		)
		if err != nil {
			return err
		}

		return assignBootstrapVulnerability(
			tx,
			asset,
			vulnerability,
		)
	})
}

// validateExistingBootstrapOrganization prevents the bootstrap process from
// deleting an organization whose fixed bootstrap ID belongs to another record.
func validateExistingBootstrapOrganization(tx *gorm.DB) error {
	var organization model.Organization

	err := tx.Unscoped().
		Where("id = ?", bootstrapOrganizationID).
		First(&organization).
		Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}

		return fmt.Errorf(
			"find existing bootstrap organization: %w",
			err,
		)
	}

	expectedName := normalize(bootstrapOrganization)
	actualName := normalize(organization.Name)

	if actualName != expectedName {
		return fmt.Errorf(
			"%w: %q belongs to organization %q",
			ErrBootstrapOrganizationConflict,
			bootstrapOrganizationID,
			organization.Name,
		)
	}

	return nil
}

// clearBootstrapData removes only records identified by the fixed bootstrap
// IDs. It does not delete every record belonging to an organization.
func clearBootstrapData(tx *gorm.DB) error {
	if err := tx.Exec(
		`DELETE FROM asset_vulnerabilities
		 WHERE asset_id = ?
		    OR vulnerability_id = ?`,
		bootstrapAssetID,
		bootstrapVulnerabilityID,
	).Error; err != nil {
		return fmt.Errorf(
			"delete bootstrap asset-vulnerability assignment: %w",
			err,
		)
	}

	if err := tx.Unscoped().
		Where("id = ?", bootstrapAssetID).
		Delete(&model.Asset{}).
		Error; err != nil {
		return fmt.Errorf("delete bootstrap asset: %w", err)
	}

	if err := tx.Unscoped().
		Where("id = ?", bootstrapVulnerabilityID).
		Delete(&model.Vulnerability{}).
		Error; err != nil {
		return fmt.Errorf(
			"delete bootstrap vulnerability: %w",
			err,
		)
	}

	if err := tx.Unscoped().
		Where("id = ?", bootstrapAssessmentID).
		Delete(&model.AssetAssessment{}).
		Error; err != nil {
		return fmt.Errorf(
			"delete bootstrap asset assessment: %w",
			err,
		)
	}

	if err := tx.Unscoped().
		Where("id = ?", bootstrapUserID).
		Delete(&model.User{}).
		Error; err != nil {
		return fmt.Errorf("delete bootstrap user: %w", err)
	}

	if err := tx.Unscoped().
		Where("id = ?", bootstrapOrganizationID).
		Delete(&model.Organization{}).
		Error; err != nil {
		return fmt.Errorf(
			"delete bootstrap organization: %w",
			err,
		)
	}

	return nil
}

// seedBootstrapOrganization creates the bootstrap organization.
func seedBootstrapOrganization(
	tx *gorm.DB,
) (model.Organization, error) {
	organization := model.Organization{
		Model: model.Model{
			ID: bootstrapOrganizationID,
		},
		Name: normalize(bootstrapOrganization),
	}

	if err := tx.Create(&organization).Error; err != nil {
		return model.Organization{}, fmt.Errorf(
			"create bootstrap organization: %w",
			err,
		)
	}

	return organization, nil
}

// seedBootstrapUser creates the bootstrap administrator.
func seedBootstrapUser(
	tx *gorm.DB,
	organizationID string,
	password string,
) (model.User, error) {
	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		config.PasswordCost(),
	)
	if err != nil {
		return model.User{}, fmt.Errorf(
			"hash bootstrap password: %w",
			err,
		)
	}

	user := model.User{
		Model: model.Model{
			ID: bootstrapUserID,
		},
		OrganizationID: organizationID,
		Username:       bootstrapUsername,
		Email:          normalize(bootstrapEmail),
		Role:           model.RoleAdmin,
		PasswordHash:   string(passwordHash),
	}

	if err := tx.Create(&user).Error; err != nil {
		return model.User{}, fmt.Errorf(
			"create bootstrap user: %w",
			err,
		)
	}

	return user, nil
}

// seedBootstrapAsset creates the sample asset and its assessment.
func seedBootstrapAsset(
	tx *gorm.DB,
	organizationID string,
	userID string,
) (model.Asset, error) {
	assessment := model.AssetAssessment{
		Model: model.Model{
			ID: bootstrapAssessmentID,
		},
		CPEReviewStatus: model.AssetCPEReviewStatusNeedsReview,
	}

	if err := tx.Create(&assessment).Error; err != nil {
		return model.Asset{}, fmt.Errorf(
			"create bootstrap asset assessment: %w",
			err,
		)
	}

	operatingSystem := bootstrapAssetOS

	asset := model.Asset{
		Model: model.Model{
			ID: bootstrapAssetID,
		},
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

	if err := tx.Create(&asset).Error; err != nil {
		return model.Asset{}, fmt.Errorf(
			"create bootstrap asset: %w",
			err,
		)
	}

	asset.Assessment = &assessment

	return asset, nil
}

// seedBootstrapVulnerability creates the sample vulnerability.
func seedBootstrapVulnerability(
	tx *gorm.DB,
	organizationID string,
	userID string,
) (model.Vulnerability, error) {
	vulnerability := model.Vulnerability{
		Model: model.Model{
			ID: bootstrapVulnerabilityID,
		},
		OrganizationID: organizationID,
		UserID:         userID,
		CVEID:          bootstrapCVEID,
		Title:          bootstrapVulnerabilityTitle,
		Severity:       bootstrapSeverity,
		Description:    bootstrapDescription,
		Status:         bootstrapStatus,
	}

	if err := tx.Create(&vulnerability).Error; err != nil {
		return model.Vulnerability{}, fmt.Errorf(
			"create bootstrap vulnerability: %w",
			err,
		)
	}

	return vulnerability, nil
}

// assignBootstrapVulnerability links the sample vulnerability to the asset.
func assignBootstrapVulnerability(
	tx *gorm.DB,
	asset model.Asset,
	vulnerability model.Vulnerability,
) error {
	if err := tx.
		Model(&asset).
		Association("Vulnerabilities").
		Append(&vulnerability); err != nil {
		return fmt.Errorf(
			"assign bootstrap vulnerability: %w",
			err,
		)
	}

	return nil
}

// normalize returns a trimmed lowercase value for identifiers that are stored
// case-insensitively.
func normalize(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
