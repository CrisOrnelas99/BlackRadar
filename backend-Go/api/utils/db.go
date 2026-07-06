// Package utils provides database connection, migration, and error translation helpers.
package utils

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"secureops/backend-go/api/config"
	"secureops/backend-go/api/model"
)

// Connect opens a GORM database connection and verifies it is reachable.
func Connect(ctx context.Context, cfg config.Config) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(cfg.DatabaseURL), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, err
	}

	return db, nil
}

// Close shuts down the underlying SQL database connection.
func Close(database *gorm.DB) error {
	sqlDB, err := database.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// TranslateDatabaseError maps known PostgreSQL constraint errors to layer-specific sentinel errors.
func TranslateDatabaseError(err error) error {
	switch {
	case err == nil:
		return nil
	case isPostgresError(err, "23503"):
		return fmt.Errorf("%w: %w", ErrForeignKeyViolation, err)
	case isPostgresError(err, "23514"):
		return fmt.Errorf("%w: %w", ErrCheckConstraintViolation, err)
	case isPostgresError(err, "23505"):
		return fmt.Errorf("%w: %w", ErrUniqueViolation, err)
	default:
		return err
	}
}

// isPostgresError reports whether err is a pgx error with the expected SQLSTATE code.
func isPostgresError(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}

// RunMigrations applies the database schema setup used by this application.
func RunMigrations(ctx context.Context, database *gorm.DB) error {
	if err := ensureOrganizationSchema(ctx, database); err != nil {
		return err
	}
	if err := ensureUserSchema(ctx, database); err != nil {
		return err
	}

	if err := database.WithContext(ctx).AutoMigrate(
		&model.Organization{},
		&model.Vulnerability{},
		&model.AssetAssessment{},
		&model.AssetVulnerability{},
		&model.Asset{},
		&model.RefreshSession{},
	); err != nil {
		return err
	}

	if err := ensureIndexes(ctx, database); err != nil {
		return err
	}

	return nil
}

// ensureOrganizationSchema creates the organization table and required columns when they do not already exist.
func ensureOrganizationSchema(ctx context.Context, database *gorm.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS organizations (
			id BIGSERIAL PRIMARY KEY,
			name TEXT NOT NULL,
			deleted_at TIMESTAMPTZ
		)`,
		`ALTER TABLE organizations ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ`,
		`DROP INDEX IF EXISTS idx_organizations_name`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_organizations_name_active ON organizations (name) WHERE deleted_at IS NULL`,
	}

	for _, statement := range statements {
		if err := database.WithContext(ctx).Exec(statement).Error; err != nil {
			return err
		}
	}

	return nil
}

// ensureUserSchema creates the user table and required columns when they do not already exist.
func ensureUserSchema(ctx context.Context, database *gorm.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id BIGSERIAL PRIMARY KEY,
			organization_id BIGINT,
			username TEXT NOT NULL,
			email VARCHAR NOT NULL,
			password_hash VARCHAR NOT NULL,
			role VARCHAR NOT NULL DEFAULT 'user',
			deleted_at TIMESTAMPTZ
		)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS organization_id BIGINT`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR NOT NULL DEFAULT 'user'`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ`,
	}

	for _, statement := range statements {
		if err := database.WithContext(ctx).Exec(statement).Error; err != nil {
			return err
		}
	}

	return nil
}

// ensureIndexes applies the indexes and constraints required by the current schema.
func ensureIndexes(ctx context.Context, database *gorm.DB) error {
	statements := []string{
		`DROP INDEX IF EXISTS idx_users_username`,
		`DROP INDEX IF EXISTS idx_users_email`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_active ON users (username) WHERE deleted_at IS NULL`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_active ON users (email) WHERE deleted_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_users_organization_id ON users (organization_id)`,
		`ALTER TABLE users DROP CONSTRAINT IF EXISTS ukr43af9ap4edm43mmtq01oddj6`,
		`ALTER TABLE users DROP CONSTRAINT IF EXISTS uk6dotkott2kjsp8vw4d0m25fb7`,
		`INSERT INTO organizations (name) VALUES ('admin_home') ON CONFLICT (name) DO NOTHING`,
		`UPDATE users SET organization_id = COALESCE(organization_id, (SELECT id FROM organizations WHERE name = 'admin_home' ORDER BY id LIMIT 1)) WHERE organization_id IS NULL`,
		`UPDATE assets SET organization_id = COALESCE(organization_id, (SELECT id FROM organizations WHERE name = 'admin_home' ORDER BY id LIMIT 1)) WHERE organization_id IS NULL`,
		`UPDATE vulnerabilities SET organization_id = COALESCE(organization_id, (SELECT id FROM organizations WHERE name = 'admin_home' ORDER BY id LIMIT 1)) WHERE organization_id IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_assets_user_id ON assets (user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_assets_organization_id ON assets (organization_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vulnerabilities_user_id ON vulnerabilities (user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vulnerabilities_organization_id ON vulnerabilities (organization_id)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_sessions_user_id ON refresh_sessions (user_id)`,
		`DROP INDEX IF EXISTS idx_vulnerabilities_cve_id`,
		`DROP INDEX IF EXISTS idx_vulnerabilities_org_cve_id`,
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM vulnerabilities WHERE organization_id IS NULL
			) AND NOT EXISTS (
				SELECT 1 FROM vulnerabilities WHERE deleted_at IS NULL GROUP BY organization_id, cve_id HAVING count(*) > 1
			) THEN
				CREATE UNIQUE INDEX IF NOT EXISTS idx_vulnerabilities_org_cve_id ON vulnerabilities (organization_id, cve_id) WHERE deleted_at IS NULL;
			END IF;
		END $$`,
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint WHERE conname = 'chk_users_role'
			) THEN
				ALTER TABLE users ADD CONSTRAINT chk_users_role CHECK (role IN ('admin', 'user'));
			END IF;
		END $$`,
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint WHERE conname = 'fk_users_organization'
			) THEN
				ALTER TABLE users ADD CONSTRAINT fk_users_organization FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE;
			END IF;
		END $$`,
		`ALTER TABLE users ALTER COLUMN organization_id SET NOT NULL`,
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint WHERE conname = 'chk_vulnerabilities_severity'
			) THEN
				ALTER TABLE vulnerabilities ADD CONSTRAINT chk_vulnerabilities_severity CHECK (severity IN ('Low', 'Medium', 'High', 'Critical'));
			END IF;
		END $$`,
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint WHERE conname = 'chk_vulnerabilities_status'
			) THEN
				ALTER TABLE vulnerabilities ADD CONSTRAINT chk_vulnerabilities_status CHECK (status IN ('Open', 'Fixed', 'In Progress'));
			END IF;
		END $$`,
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint WHERE conname = 'fk_assets_user'
			) THEN
				ALTER TABLE assets ADD CONSTRAINT fk_assets_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
			END IF;
		END $$`,
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint WHERE conname = 'fk_assets_organization'
			) THEN
				ALTER TABLE assets ADD CONSTRAINT fk_assets_organization FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE;
			END IF;
		END $$`,
		`ALTER TABLE assets ADD COLUMN IF NOT EXISTS vendor TEXT`,
		`ALTER TABLE assets ADD COLUMN IF NOT EXISTS product TEXT`,
		`ALTER TABLE assets ADD COLUMN IF NOT EXISTS version TEXT`,
		`ALTER TABLE assets ADD COLUMN IF NOT EXISTS device_model TEXT`,
		`ALTER TABLE assets ALTER COLUMN risk_level DROP DEFAULT`,
		`ALTER TABLE assets ALTER COLUMN risk_level DROP NOT NULL`,
		`ALTER TABLE assets ADD COLUMN IF NOT EXISTS asset_assessment_id BIGINT`,
		`ALTER TABLE assets ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ`,
		`ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ`,
		`ALTER TABLE asset_assessments ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ`,
		`ALTER TABLE asset_vulnerabilities ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ`,
		`ALTER TABLE asset_vulnerabilities ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ`,
		`UPDATE asset_vulnerabilities SET created_at = COALESCE(created_at, NOW()) WHERE created_at IS NULL`,
		`ALTER TABLE asset_vulnerabilities DROP CONSTRAINT IF EXISTS asset_vulnerabilities_pkey`,
		`DROP INDEX IF EXISTS idx_asset_vulnerabilities_active`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_vulnerabilities_active ON asset_vulnerabilities (asset_id, vulnerability_id) WHERE deleted_at IS NULL`,
		`ALTER TABLE assets DROP CONSTRAINT IF EXISTS fk_assets_asset_assessment`,
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
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint WHERE conname = 'chk_asset_assessments_cpe_review_status'
			) THEN
				ALTER TABLE asset_assessments ADD CONSTRAINT chk_asset_assessments_cpe_review_status CHECK (cpe_review_status IN ('accepted', 'needs_review', 'rejected'));
			END IF;
		END $$`,
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
		`ALTER TABLE assets ALTER COLUMN organization_id SET NOT NULL`,
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint WHERE conname = 'fk_vulnerabilities_user'
			) AND NOT EXISTS (
				SELECT 1 FROM vulnerabilities WHERE user_id = 0
			) THEN
				ALTER TABLE vulnerabilities ADD CONSTRAINT fk_vulnerabilities_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
			END IF;
		END $$`,
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint WHERE conname = 'fk_vulnerabilities_organization'
			) THEN
				ALTER TABLE vulnerabilities ADD CONSTRAINT fk_vulnerabilities_organization FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE;
			END IF;
		END $$`,
		`ALTER TABLE vulnerabilities ALTER COLUMN organization_id SET NOT NULL`,
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint WHERE conname = 'fk_refresh_sessions_user'
			) THEN
				ALTER TABLE refresh_sessions ADD CONSTRAINT fk_refresh_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
			END IF;
		END $$`,
		`ALTER TABLE asset_vulnerabilities DROP CONSTRAINT IF EXISTS fkavovmmqdpqv6hacqhae27ngt1`,
		`ALTER TABLE asset_vulnerabilities DROP CONSTRAINT IF EXISTS fkpldrve7axqj2xnyb09ojqmd02`,
	}

	for _, statement := range statements {
		if err := database.WithContext(ctx).Exec(statement).Error; err != nil {
			return err
		}
	}

	if err := remapAssetAssessmentIDs(ctx, database); err != nil {
		return err
	}

	postRemapStatements := []string{
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_asset_assessment_id ON assets (asset_assessment_id)`,
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint WHERE conname = 'fk_assets_asset_assessment'
			) THEN
				ALTER TABLE assets ADD CONSTRAINT fk_assets_asset_assessment FOREIGN KEY (asset_assessment_id) REFERENCES asset_assessments(id) ON UPDATE CASCADE;
			END IF;
		END $$`,
		`ALTER TABLE assets ALTER COLUMN asset_assessment_id SET NOT NULL`,
	}

	for _, statement := range postRemapStatements {
		if err := database.WithContext(ctx).Exec(statement).Error; err != nil {
			return err
		}
	}

	return nil
}

// remapAssetAssessmentIDs gives existing asset assessment rows arbitrary IDs so they are decoupled from asset IDs.
func remapAssetAssessmentIDs(ctx context.Context, database *gorm.DB) error {
	type idRow struct {
		ID int64 `gorm:"column:id"`
	}

	var assessmentIDs []idRow
	if err := database.WithContext(ctx).Table("asset_assessments").Order("id").Find(&assessmentIDs).Error; err != nil {
		return err
	}
	if len(assessmentIDs) == 0 {
		return nil
	}

	var assetIDs []int64
	if err := database.WithContext(ctx).Table("assets").Order("id").Pluck("id", &assetIDs).Error; err != nil {
		return err
	}

	reservedIDs := make(map[int64]struct{}, len(assessmentIDs)+len(assetIDs))
	for _, id := range assetIDs {
		reservedIDs[id] = struct{}{}
	}
	for _, row := range assessmentIDs {
		reservedIDs[row.ID] = struct{}{}
	}

	return database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, row := range assessmentIDs {
			newID, err := nextDistinctID(reservedIDs, row.ID)
			if err != nil {
				return err
			}
			if err := tx.Exec(`UPDATE asset_assessments SET id = ? WHERE id = ?`, newID, row.ID).Error; err != nil {
				return err
			}
			if err := tx.Exec(`UPDATE assets SET asset_assessment_id = ? WHERE asset_assessment_id = ?`, newID, row.ID).Error; err != nil {
				return err
			}
			reservedIDs[newID] = struct{}{}
		}
		return nil
	})
}

// nextDistinctID returns a random identifier that does not collide with any reserved IDs or the excluded value.
func nextDistinctID(reserved map[int64]struct{}, excluded int64) (int64, error) {
	for attempts := 0; attempts < 1024; attempts++ {
		id := NewRandomID()
		if id == excluded {
			continue
		}
		if _, exists := reserved[id]; exists {
			continue
		}
		return id, nil
	}
	return 0, fmt.Errorf("exhausted random id retries while remapping asset assessments")
}
