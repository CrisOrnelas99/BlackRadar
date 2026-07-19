package db

// This file applies the runtime schema migrations and supporting safety checks.

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"blackradar/api/model"
)

// RunMigrations applies the schema setup used by this application.
//
// This project still performs runtime startup migrations today. The schema work
// is kept here for now, but it is intentionally split from connection and error
// translation logic so it can be replaced cleanly by versioned migrations later.
func RunMigrations(ctx context.Context, database *gorm.DB) error {
	if database == nil {
		return fmt.Errorf("run migrations: database is required")
	}

	if err := executeStatements(
		ctx,
		database,
		"extensions",
		[]string{`CREATE EXTENSION IF NOT EXISTS pgcrypto`},
	); err != nil {
		return err
	}

	if err := autoMigrateSchema(ctx, database); err != nil {
		return err
	}

	if err := executeStatements(
		ctx,
		database,
		"indexes and constraints",
		schemaStatements(),
	); err != nil {
		return err
	}

	if err := executeStatements(
		ctx,
		database,
		"asset assessment remap",
		assetAssessmentMigrationStatements(),
	); err != nil {
		return err
	}

	if err := executeStatements(
		ctx,
		database,
		"post remap",
		postRemapStatements(),
	); err != nil {
		return err
	}

	return nil
}

// autoMigrateSchema runs the GORM-managed schema updates for the current models.
func autoMigrateSchema(ctx context.Context, database *gorm.DB) error {
	if err := database.WithContext(ctx).AutoMigrate(
		&model.User{},
		&model.Vulnerability{},
		&model.AssetAssessment{},
		&model.AssetVulnerability{},
		&model.Asset{},
		&model.RefreshSession{},
	); err != nil {
		return fmt.Errorf("auto migrate schema: %w", err)
	}

	return nil
}

// executeStatements runs a named group of SQL statements and adds statement
// index context to any returned error.
func executeStatements(
	ctx context.Context,
	database *gorm.DB,
	group string,
	statements []string,
) error {
	for index, statement := range statements {
		if err := database.WithContext(ctx).Exec(statement).Error; err != nil {
			return fmt.Errorf(
				"%s statement %d failed: %w",
				group,
				index+1,
				err,
			)
		}
	}

	return nil
}

// schemaStatements returns the ordered index, constraint, and column updates
// required by the current runtime schema.
func schemaStatements() []string {
	return []string{
		`DROP INDEX IF EXISTS idx_users_username`,
		`DROP INDEX IF EXISTS idx_users_email`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_active ON users (username) WHERE deleted_at IS NULL`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_active ON users (email) WHERE deleted_at IS NULL`,
		`DROP INDEX IF EXISTS idx_users_organization_id`,
		`ALTER TABLE users DROP CONSTRAINT IF EXISTS ukr43af9ap4edm43mmtq01oddj6`,
		`ALTER TABLE users DROP CONSTRAINT IF EXISTS uk6dotkott2kjsp8vw4d0m25fb7`,
		`CREATE INDEX IF NOT EXISTS idx_assets_user_id ON assets (user_id)`,
		`DROP INDEX IF EXISTS idx_assets_organization_id`,
		`CREATE INDEX IF NOT EXISTS idx_vulnerabilities_user_id ON vulnerabilities (user_id)`,
		`DROP INDEX IF EXISTS idx_vulnerabilities_organization_id`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_sessions_user_id ON refresh_sessions (user_id)`,
		`DROP INDEX IF EXISTS idx_vulnerabilities_cve_id`,
		`DROP INDEX IF EXISTS idx_vulnerabilities_org_cve_id`,
		`DROP INDEX IF EXISTS idx_vulnerabilities_user_cve_id`,
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM vulnerabilities WHERE user_id IS NULL
			) AND NOT EXISTS (
				SELECT 1 FROM vulnerabilities WHERE deleted_at IS NULL GROUP BY user_id, cve_id HAVING count(*) > 1
			) THEN
				CREATE UNIQUE INDEX IF NOT EXISTS idx_vulnerabilities_user_cve_id ON vulnerabilities (user_id, cve_id) WHERE deleted_at IS NULL;
			END IF;
		END $$`,
		constraintStatement(
			"chk_users_role",
			"users",
			`ALTER TABLE users ADD CONSTRAINT chk_users_role CHECK (role IN ('admin', 'user'))`,
		),
		`ALTER TABLE users DROP CONSTRAINT IF EXISTS fk_users_organization`,
		`ALTER TABLE users DROP COLUMN IF EXISTS organization_id`,
		constraintStatement(
			"chk_vulnerabilities_severity",
			"vulnerabilities",
			`ALTER TABLE vulnerabilities ADD CONSTRAINT chk_vulnerabilities_severity CHECK (severity IN ('Low', 'Medium', 'High', 'Critical'))`,
		),
		constraintStatement(
			"chk_vulnerabilities_status",
			"vulnerabilities",
			`ALTER TABLE vulnerabilities ADD CONSTRAINT chk_vulnerabilities_status CHECK (status IN ('Open', 'Fixed', 'In Progress'))`,
		),
		constraintStatement(
			"fk_assets_user",
			"assets",
			`ALTER TABLE assets ADD CONSTRAINT fk_assets_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE`,
		),
		`ALTER TABLE assets DROP CONSTRAINT IF EXISTS fk_assets_organization`,
		`ALTER TABLE assets ADD COLUMN IF NOT EXISTS vendor TEXT`,
		`ALTER TABLE assets ADD COLUMN IF NOT EXISTS product TEXT`,
		`ALTER TABLE assets ADD COLUMN IF NOT EXISTS version TEXT`,
		`ALTER TABLE assets ADD COLUMN IF NOT EXISTS device_model TEXT`,
		`ALTER TABLE assets ALTER COLUMN risk_level DROP DEFAULT`,
		`ALTER TABLE assets ALTER COLUMN risk_level DROP NOT NULL`,
		`ALTER TABLE assets ADD COLUMN IF NOT EXISTS asset_assessment_id UUID`,
		`ALTER TABLE assets ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ`,
		`ALTER TABLE assets ADD COLUMN IF NOT EXISTS updated_by_id UUID`,
		`ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ`,
		`ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS updated_by_id UUID`,
		`ALTER TABLE asset_assessments ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ`,
		`ALTER TABLE asset_assessments ADD COLUMN IF NOT EXISTS updated_by_id UUID`,
		`ALTER TABLE asset_vulnerabilities ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ`,
		`ALTER TABLE asset_vulnerabilities ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ`,
		`UPDATE asset_vulnerabilities SET created_at = COALESCE(created_at, NOW()) WHERE created_at IS NULL`,
		`ALTER TABLE asset_vulnerabilities DROP CONSTRAINT IF EXISTS asset_vulnerabilities_pkey`,
		`DROP INDEX IF EXISTS idx_asset_vulnerabilities_active`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_vulnerabilities_active ON asset_vulnerabilities (asset_id, vulnerability_id) WHERE deleted_at IS NULL`,
		`ALTER TABLE assets DROP CONSTRAINT IF EXISTS fk_assets_asset_assessment`,
		`ALTER TABLE assets DROP COLUMN IF EXISTS organization_id`,
		constraintStatement(
			"fk_vulnerabilities_user",
			"vulnerabilities",
			`ALTER TABLE vulnerabilities ADD CONSTRAINT fk_vulnerabilities_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE`,
		),
		`ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS fk_vulnerabilities_organization`,
		`ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS organization_id`,
		constraintStatement(
			"fk_refresh_sessions_user",
			"refresh_sessions",
			`ALTER TABLE refresh_sessions ADD CONSTRAINT fk_refresh_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE`,
		),
		`ALTER TABLE asset_vulnerabilities DROP CONSTRAINT IF EXISTS fkavovmmqdpqv6hacqhae27ngt1`,
		`ALTER TABLE asset_vulnerabilities DROP CONSTRAINT IF EXISTS fkpldrve7axqj2xnyb09ojqmd02`,
		`DROP INDEX IF EXISTS idx_organizations_name_active`,
		`DROP TABLE IF EXISTS organizations`,
	}
}

// assetAssessmentMigrationStatements returns the legacy asset assessment remap
// and cleanup statements needed during startup migration.
func assetAssessmentMigrationStatements() []string {
	return []string{
		`DO $$
		DECLARE
			has_legacy_match_columns BOOLEAN;
		BEGIN
			SELECT EXISTS (
				SELECT 1
				FROM information_schema.columns
				WHERE table_schema = current_schema()
				  AND table_name = 'assets'
				  AND column_name = 'risk_score'
			) INTO has_legacy_match_columns;

			IF has_legacy_match_columns THEN
				INSERT INTO asset_assessments (
					id,
					risk_score,
					product_fingerprint,
					selected_cpe,
					cpe_confidence,
					cpe_review_status,
					cpe_review_notes,
					cpe_candidate_count,
					cpe_matched_at,
					created_at,
					updated_at
				)
				SELECT
					a.id,
					COALESCE(a.risk_score, 0),
					a.product_fingerprint,
					a.selected_cpe,
					a.cpe_confidence,
					COALESCE(NULLIF(a.cpe_review_status, ''), 'needs_review'),
					a.cpe_review_notes,
					COALESCE(a.cpe_candidate_count, 0),
					a.cpe_matched_at,
					COALESCE(a.created_at, NOW()),
					COALESCE(a.updated_at, NOW())
				FROM assets a
				WHERE a.asset_assessment_id IS NULL
				ON CONFLICT (id) DO NOTHING;
			ELSE
				INSERT INTO asset_assessments (
					id,
					risk_score,
					cpe_review_status,
					cpe_candidate_count,
					created_at,
					updated_at
				)
				SELECT
					a.id,
					0,
					'needs_review',
					0,
					COALESCE(a.created_at, NOW()),
					COALESCE(a.updated_at, NOW())
				FROM assets a
				WHERE a.asset_assessment_id IS NULL
				ON CONFLICT (id) DO NOTHING;
			END IF;
		END $$`,
		`UPDATE assets SET asset_assessment_id = id WHERE asset_assessment_id IS NULL`,
		constraintStatement(
			"chk_asset_assessments_cpe_review_status",
			"asset_assessments",
			`ALTER TABLE asset_assessments ADD CONSTRAINT chk_asset_assessments_cpe_review_status CHECK (cpe_review_status IN ('accepted', 'needs_review', 'rejected'))`,
		),
		`ALTER TABLE asset_assessments ALTER COLUMN cpe_review_status SET DEFAULT 'needs_review'`,
		`ALTER TABLE asset_assessments ALTER COLUMN cpe_review_status SET NOT NULL`,
		`ALTER TABLE asset_assessments ALTER COLUMN cpe_candidate_count SET DEFAULT 0`,
		`ALTER TABLE asset_assessments ALTER COLUMN cpe_candidate_count SET NOT NULL`,
		`ALTER TABLE asset_assessments ALTER COLUMN risk_score SET DEFAULT 0`,
		`ALTER TABLE asset_assessments ALTER COLUMN risk_score SET NOT NULL`,
		`ALTER TABLE assets DROP COLUMN IF EXISTS risk_score`,
		`ALTER TABLE assets DROP COLUMN IF EXISTS product_fingerprint`,
		`ALTER TABLE assets DROP COLUMN IF EXISTS selected_cpe`,
		`ALTER TABLE assets DROP COLUMN IF EXISTS cpe_confidence`,
		`ALTER TABLE assets DROP COLUMN IF EXISTS cpe_review_status`,
		`ALTER TABLE assets DROP COLUMN IF EXISTS cpe_review_notes`,
		`ALTER TABLE assets DROP COLUMN IF EXISTS cpe_candidate_count`,
		`ALTER TABLE assets DROP COLUMN IF EXISTS cpe_matched_at`,
		`ALTER TABLE assets DROP CONSTRAINT IF EXISTS chk_assets_cpe_review_status`,
	}
}

// postRemapStatements returns the final asset assessment constraints that must
// run after the remap finishes.
func postRemapStatements() []string {
	return []string{
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_asset_assessment_id ON assets (asset_assessment_id)`,
		constraintStatement(
			"fk_assets_asset_assessment",
			"assets",
			`ALTER TABLE assets ADD CONSTRAINT fk_assets_asset_assessment FOREIGN KEY (asset_assessment_id) REFERENCES asset_assessments(id) ON UPDATE CASCADE`,
		),
		`ALTER TABLE assets ALTER COLUMN asset_assessment_id SET NOT NULL`,
	}
}

// constraintStatement builds a guarded ALTER statement that only runs when the
// named table-scoped constraint does not already exist.
func constraintStatement(
	constraintName string,
	tableName string,
	alterStatement string,
) string {
	return fmt.Sprintf(
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1
				FROM pg_constraint
				WHERE conname = '%s'
				  AND conrelid = '%s'::regclass
			) THEN
				%s;
			END IF;
		END $$`,
		constraintName,
		tableName,
		alterStatement,
	)
}
