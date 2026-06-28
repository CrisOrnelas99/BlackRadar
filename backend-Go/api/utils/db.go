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
		&model.Asset{},
		&model.RefreshSession{},
	); err != nil {
		return err
	}

	return ensureIndexes(ctx, database)
}

// ensureOrganizationSchema creates the organization table and required columns when they do not already exist.
func ensureOrganizationSchema(ctx context.Context, database *gorm.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS organizations (
			id BIGSERIAL PRIMARY KEY,
			name TEXT NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_organizations_name ON organizations (name)`,
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
			role VARCHAR NOT NULL DEFAULT 'user'
		)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS organization_id BIGINT`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR NOT NULL DEFAULT 'user'`,
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
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users (username)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (email)`,
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
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM vulnerabilities WHERE organization_id IS NULL
			) AND NOT EXISTS (
				SELECT 1 FROM vulnerabilities GROUP BY organization_id, cve_id HAVING count(*) > 1
			) THEN
				CREATE UNIQUE INDEX IF NOT EXISTS idx_vulnerabilities_org_cve_id ON vulnerabilities (organization_id, cve_id);
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

	return nil
}
