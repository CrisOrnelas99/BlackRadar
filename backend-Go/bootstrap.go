package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"secureops/backend-go/api/config"
	"secureops/backend-go/api/model"
)

const (
	bootstrapUsername = "system_admin"
	bootstrapEmail    = "Test@gmail.com"
	bootstrapPassword = "Password123!"

	bootstrapUserID          int64 = 7700000000000000001
	bootstrapAssetID         int64 = 7700000000000000002
	bootstrapVulnerabilityID int64 = 7700000000000000003

	bootstrapAssetName        = "Test Device"
	bootstrapAssetType        = "Device"
	bootstrapAssetIPAddress   = "10.0.0.10"
	bootstrapAssetOS          = "Linux"
	bootstrapAssetOwner       = "system_admin"
	bootstrapAssetCriticality = "High"

	bootstrapCVEID              = "CVE-2021-44228"
	bootstrapVulnerabilityTitle = "Apache Log4j Remote Code Execution"
	bootstrapSeverity           = "Critical"
	bootstrapStatus             = "Open"
	bootstrapDescription        = "Example NVD-backed CVE used for local testing."
)

func runBootstrap(ctx context.Context, database *gorm.DB, cfg config.Config) error {
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

		user, err := seedBootstrapUser(ctx, tx)
		if err != nil {
			return err
		}

		asset, err := seedBootstrapAsset(ctx, tx, user.ID)
		if err != nil {
			return err
		}

		vulnerability, err := seedBootstrapVulnerability(ctx, tx, user.ID)
		if err != nil {
			return err
		}

		return assignBootstrapVulnerability(ctx, tx, asset, vulnerability)
	})
}

func clearBootstrapData(ctx context.Context, database *gorm.DB) error {
	email := strings.ToLower(strings.TrimSpace(bootstrapEmail))
	var user model.User
	err := database.WithContext(ctx).
		Where("username = ? OR email = ?", bootstrapUsername, email).
		First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("find bootstrap user for cleanup: %w", err)
	}

	if err := database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(
			`DELETE FROM asset_vulnerabilities
			 WHERE asset_id IN (SELECT id FROM assets WHERE user_id = ?)
			    OR vulnerability_id IN (SELECT id FROM vulnerabilities WHERE user_id = ?)`,
			user.ID, user.ID,
		).Error; err != nil {
			return fmt.Errorf("delete bootstrap asset vulnerabilities: %w", err)
		}
		if err := tx.Exec(`DELETE FROM assets WHERE user_id = ?`, user.ID).Error; err != nil {
			return fmt.Errorf("delete bootstrap assets: %w", err)
		}
		if err := tx.Exec(`DELETE FROM vulnerabilities WHERE user_id = ?`, user.ID).Error; err != nil {
			return fmt.Errorf("delete bootstrap vulnerabilities: %w", err)
		}
		if err := tx.Delete(&user).Error; err != nil {
			return fmt.Errorf("delete bootstrap user: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

func seedBootstrapUser(ctx context.Context, database *gorm.DB) (model.User, error) {
	email := strings.ToLower(strings.TrimSpace(bootstrapEmail))
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(bootstrapPassword), config.PasswordCost())
	if err != nil {
		return model.User{}, fmt.Errorf("hash bootstrap password: %w", err)
	}

	user := model.User{
		ID:           bootstrapUserID,
		Username:     bootstrapUsername,
		Email:        email,
		Role:         model.RoleAdmin,
		PasswordHash: string(passwordHash),
	}
	if err := database.WithContext(ctx).Create(&user).Error; err != nil {
		return model.User{}, fmt.Errorf("create bootstrap user: %w", err)
	}

	return user, nil
}

func seedBootstrapAsset(ctx context.Context, database *gorm.DB, userID int64) (model.Asset, error) {
	operatingSystem := bootstrapAssetOS
	asset := model.Asset{
		ID:              bootstrapAssetID,
		UserID:          userID,
		Name:            bootstrapAssetName,
		Type:            bootstrapAssetType,
		IPAddress:       bootstrapAssetIPAddress,
		OperatingSystem: &operatingSystem,
		Owner:           bootstrapAssetOwner,
		Criticality:     bootstrapAssetCriticality,
		RiskScore:       0,
		RiskLevel:       "Low",
	}
	if err := database.WithContext(ctx).Create(&asset).Error; err != nil {
		return model.Asset{}, fmt.Errorf("create bootstrap asset: %w", err)
	}

	return asset, nil
}

func seedBootstrapVulnerability(ctx context.Context, database *gorm.DB, userID int64) (model.Vulnerability, error) {
	vulnerability := model.Vulnerability{
		ID:          bootstrapVulnerabilityID,
		UserID:      userID,
		CVEID:       bootstrapCVEID,
		Title:       bootstrapVulnerabilityTitle,
		Severity:    bootstrapSeverity,
		Description: bootstrapDescription,
		Status:      bootstrapStatus,
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
		Where("asset_id = ? AND vulnerability_id = ?", asset.ID, vulnerability.ID).
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
