package bootstrap

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"blackradar/api/model"
	"blackradar/api/platform/config"
)

const (
	bootstrapUserID  = model.SystemAdminID
	bootstrapAssetID = "77000000-0000-4000-8000-000000000002"

	bootstrapVulnerabilityID = "77000000-0000-4000-8000-000000000003"
	bootstrapAssessmentID    = "77000000-0000-4000-8000-000000000004"

	bootstrapDynamoDBAssetID         = "77000000-0000-4000-8000-000000000005"
	bootstrapDynamoDBVulnerabilityID = "77000000-0000-4000-8000-000000000006"
	bootstrapDynamoDBAssessmentID    = "77000000-0000-4000-8000-000000000007"

	bootstrapUsername = "system_admin"
	bootstrapEmail    = "system_admin@example.invalid"
	bootstrapFullName = "System Admin"

	bootstrapAssetName        = "Microsoft Windows App Client"
	bootstrapAssetType        = "Application"
	bootstrapAssetOS          = "Windows"
	bootstrapAssetVendor      = "Microsoft"
	bootstrapAssetProduct     = "Windows App"
	bootstrapAssetVersion     = "2.0.1313"
	bootstrapAssetOwner       = "system_admin"
	bootstrapAssetCriticality = "Medium"
	bootstrapAssetRiskLevel   = "Low"

	bootstrapCVEID              = "CVE-2021-44228"
	bootstrapVulnerabilityTitle = "Apache Log4j Remote Code Execution"
	bootstrapSeverity           = "Critical"
	bootstrapStatus             = "Fixed"
	bootstrapDescription        = "Apache Log4j2 JNDI remote code execution. AWS reports that Amazon DynamoDB and DAX were updated to mitigate this CVE; retained here as a historical dependency finding for local testing."

	bootstrapDynamoDBAssetName          = "Amazon DynamoDB"
	bootstrapDynamoDBAssetType          = "Cloud Database"
	bootstrapDynamoDBVendor             = "Amazon Web Services"
	bootstrapDynamoDBProduct            = "DynamoDB Local"
	bootstrapDynamoDBVersion            = "2.0.x"
	bootstrapDynamoDBOwner              = "system_admin"
	bootstrapDynamoDBCriticality        = "Critical"
	bootstrapDynamoDBRiskLevel          = "Critical"
	bootstrapDynamoDBCVEID              = "CVE-2022-1471"
	bootstrapDynamoDBVulnerabilityTitle = "SnakeYAML Unsafe Deserialization"
	bootstrapDynamoDBSeverity           = "Critical"
	bootstrapDynamoDBStatus             = "Open"
	bootstrapDynamoDBDescription        = "DynamoDB Local 2.0.x includes a vulnerable SnakeYAML deserialization path. AWS recommends upgrading DynamoDB Local to 2.5.3 or later."
)

// seedDevData recreates the known bootstrap records inside one transaction.
func seedDevData(
	ctx context.Context,
	database *gorm.DB,
	password string,
) error {
	return database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := clearBootstrapData(tx); err != nil {
			return err
		}

		user, err := seedBootstrapUser(
			tx,
			password,
		)
		if err != nil {
			return err
		}

		_, err = seedBootstrapAsset(
			tx,
			user.ID,
		)
		if err != nil {
			return err
		}

		vulnerability, err := seedBootstrapVulnerability(
			tx,
			user.ID,
		)
		if err != nil {
			return err
		}

		dynamoDBAsset, err := seedBootstrapDynamoDBAsset(tx, user.ID)
		if err != nil {
			return err
		}

		dynamoDBVulnerability, err := seedBootstrapDynamoDBVulnerability(tx, user.ID)
		if err != nil {
			return err
		}

		if err := assignBootstrapVulnerability(tx, dynamoDBAsset, vulnerability); err != nil {
			return err
		}

		return assignBootstrapVulnerability(tx, dynamoDBAsset, dynamoDBVulnerability)
	})
}

// clearBootstrapData removes only records identified by the fixed bootstrap IDs.
func clearBootstrapData(tx *gorm.DB) error {
	if err := tx.Exec(
		`DELETE FROM asset_vulnerabilities
		 WHERE asset_id = ?
		    OR asset_id = ?
		    OR vulnerability_id = ?
		    OR vulnerability_id = ?`,
		bootstrapAssetID,
		bootstrapDynamoDBAssetID,
		bootstrapVulnerabilityID,
		bootstrapDynamoDBVulnerabilityID,
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
		Where("id = ?", bootstrapDynamoDBAssetID).
		Delete(&model.Asset{}).
		Error; err != nil {
		return fmt.Errorf("delete bootstrap DynamoDB asset: %w", err)
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
		Where("id = ?", bootstrapDynamoDBVulnerabilityID).
		Delete(&model.Vulnerability{}).
		Error; err != nil {
		return fmt.Errorf("delete bootstrap DynamoDB vulnerability: %w", err)
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
		Where("id = ?", bootstrapDynamoDBAssessmentID).
		Delete(&model.AssetAssessment{}).
		Error; err != nil {
		return fmt.Errorf("delete bootstrap DynamoDB asset assessment: %w", err)
	}

	if err := tx.
		Where("user_id = ?", bootstrapUserID).
		Delete(&model.RefreshSession{}).
		Error; err != nil {
		return fmt.Errorf("delete bootstrap refresh sessions: %w", err)
	}

	return nil
}

// seedBootstrapUser creates or refreshes the bootstrap administrator without
// deleting organization-scoped development data.
func seedBootstrapUser(
	tx *gorm.DB,
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

	user := newBootstrapUser(string(passwordHash))
	result := tx.Unscoped().
		Model(&model.User{}).
		Where("id = ?", user.ID).
		Updates(map[string]any{
			"full_name":            user.FullName,
			"username":             user.Username,
			"email":                user.Email,
			"role":                 user.Role,
			"organization_id":      model.SingleOrganizationID,
			"password_hash":        user.PasswordHash,
			"failed_login_count":   0,
			"last_failed_login_at": nil,
			"locked_until":         nil,
			"deleted_at":           nil,
		})
	if result.Error != nil {
		return model.User{}, fmt.Errorf(
			"refresh bootstrap user: %w",
			result.Error,
		)
	}

	if result.RowsAffected == 0 {
		if err := tx.Create(&user).Error; err != nil {
			return model.User{}, fmt.Errorf(
				"create bootstrap user: %w",
				err,
			)
		}
	}

	return user, nil
}

// newBootstrapUser builds the fixed local development administrator.
func newBootstrapUser(passwordHash string) model.User {
	return model.User{
		Model: model.Model{
			ID: bootstrapUserID,
		},
		OrganizationID: model.SingleOrganizationID,
		FullName:       bootstrapFullName,
		Username:       bootstrapUsername,
		Email:          normalize(bootstrapEmail),
		Role:           model.RoleMaster,
		PasswordHash:   passwordHash,
	}
}

// seedBootstrapAsset creates the sample asset and its assessment.
func seedBootstrapAsset(
	tx *gorm.DB,
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

	asset := newBootstrapAsset(userID, assessment.ID)

	if err := tx.Create(&asset).Error; err != nil {
		return model.Asset{}, fmt.Errorf(
			"create bootstrap asset: %w",
			err,
		)
	}

	asset.Assessment = &assessment

	return asset, nil
}

// newBootstrapAsset builds the unassigned Windows App test asset.
func newBootstrapAsset(userID string, assessmentID string) model.Asset {
	operatingSystem := bootstrapAssetOS
	return model.Asset{
		Model: model.Model{
			ID: bootstrapAssetID,
		},
		UserID:            userID,
		OrganizationID:    model.SingleOrganizationID,
		AssetAssessmentID: &assessmentID,
		Name:              bootstrapAssetName,
		Type:              bootstrapAssetType,
		OperatingSystem:   &operatingSystem,
		Vendor:            stringPointer(bootstrapAssetVendor),
		Product:           stringPointer(bootstrapAssetProduct),
		Version:           stringPointer(bootstrapAssetVersion),
		Owner:             bootstrapAssetOwner,
		Criticality:       bootstrapAssetCriticality,
		RiskLevel:         stringPointer(bootstrapAssetRiskLevel),
	}
}

// seedBootstrapVulnerability creates the sample vulnerability.
func seedBootstrapVulnerability(
	tx *gorm.DB,
	userID string,
) (model.Vulnerability, error) {
	vulnerability := model.Vulnerability{
		Model: model.Model{
			ID: bootstrapVulnerabilityID,
		},
		UserID:         userID,
		OrganizationID: model.SingleOrganizationID,
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

// seedBootstrapDynamoDBAsset creates a local DynamoDB exposure simulation.
func seedBootstrapDynamoDBAsset(
	tx *gorm.DB,
	userID string,
) (model.Asset, error) {
	productFingerprint := "amazon web services dynamodb local 2.0.x"
	reviewNotes := "This seed models DynamoDB Local, not the managed AWS service; verify the runtime and version before treating the findings as applicable."
	assessment := model.AssetAssessment{
		Model: model.Model{
			ID: bootstrapDynamoDBAssessmentID,
		},
		RiskScore:          10,
		ProductFingerprint: &productFingerprint,
		CPEReviewStatus:    model.AssetCPEReviewStatusNeedsReview,
		CPEReviewNotes:     &reviewNotes,
	}

	if err := tx.Create(&assessment).Error; err != nil {
		return model.Asset{}, fmt.Errorf("create bootstrap DynamoDB asset assessment: %w", err)
	}

	asset := model.Asset{
		Model: model.Model{
			ID: bootstrapDynamoDBAssetID,
		},
		UserID:            userID,
		OrganizationID:    model.SingleOrganizationID,
		AssetAssessmentID: &assessment.ID,
		Name:              bootstrapDynamoDBAssetName,
		Type:              bootstrapDynamoDBAssetType,
		Vendor:            stringPointer(bootstrapDynamoDBVendor),
		Product:           stringPointer(bootstrapDynamoDBProduct),
		Version:           stringPointer(bootstrapDynamoDBVersion),
		Owner:             bootstrapDynamoDBOwner,
		Criticality:       bootstrapDynamoDBCriticality,
		RiskLevel:         stringPointer(bootstrapDynamoDBRiskLevel),
	}

	if err := tx.Create(&asset).Error; err != nil {
		return model.Asset{}, fmt.Errorf("create bootstrap DynamoDB asset: %w", err)
	}

	asset.Assessment = &assessment
	return asset, nil
}

// seedBootstrapDynamoDBVulnerability creates a real AWS-bulletin-backed seed finding.
func seedBootstrapDynamoDBVulnerability(
	tx *gorm.DB,
	userID string,
) (model.Vulnerability, error) {
	vulnerability := model.Vulnerability{
		Model: model.Model{
			ID: bootstrapDynamoDBVulnerabilityID,
		},
		UserID:         userID,
		OrganizationID: model.SingleOrganizationID,
		CVEID:          bootstrapDynamoDBCVEID,
		Title:          bootstrapDynamoDBVulnerabilityTitle,
		Severity:       bootstrapDynamoDBSeverity,
		Description:    bootstrapDynamoDBDescription,
		Status:         bootstrapDynamoDBStatus,
	}

	if err := tx.Create(&vulnerability).Error; err != nil {
		return model.Vulnerability{}, fmt.Errorf("create bootstrap DynamoDB vulnerability: %w", err)
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

func stringPointer(value string) *string {
	return &value
}
