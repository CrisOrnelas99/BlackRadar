package db

import (
	"strings"
	"testing"
)

func TestRelationshipSoftDeleteColumnPrecedesDuplicateRemapping(t *testing.T) {
	statements := schemaStatements()
	columnIndex := -1
	remappingIndex := -1
	for index, statement := range statements {
		if strings.Contains(statement, "ALTER TABLE asset_vulnerabilities ADD COLUMN IF NOT EXISTS deleted_at") {
			columnIndex = index
		}
		if strings.Contains(statement, "WITH ranked_vulnerabilities AS") && strings.Contains(statement, "remappable_relationships") {
			remappingIndex = index
		}
	}

	if columnIndex == -1 || remappingIndex == -1 || columnIndex >= remappingIndex {
		t.Fatalf("expected asset vulnerability deleted_at column before duplicate remapping: column=%d remapping=%d", columnIndex, remappingIndex)
	}
}

func TestUserRoleConstraintAllowsMaster(t *testing.T) {
	for _, statement := range schemaStatements() {
		if strings.Contains(statement, "chk_users_role") && !strings.Contains(statement, "'master'") {
			t.Fatalf("expected user role constraint to allow master, got %q", statement)
		}
	}
}

func TestSchemaStatementsDoNotAssignFallbackTenant(t *testing.T) {
	for _, statement := range schemaStatements() {
		if strings.Contains(statement, "admin_home") {
			t.Fatalf("expected schema statements to avoid fallback tenant assignment, found %q", statement)
		}
	}
}

func TestRuntimeMigrationStatementsDoNotContainDestructiveOperations(t *testing.T) {
	statementGroups := [][]string{
		schemaStatements(),
		assetAssessmentMigrationStatements(),
		postRemapStatements(),
	}

	for _, statements := range statementGroups {
		for _, statement := range statements {
			if strings.Contains(strings.ToUpper(statement), "DROP ") &&
				!strings.Contains(statement, "DROP INDEX IF EXISTS idx_vulnerabilities_user_cve_id") &&
				!strings.Contains(statement, "DROP CONSTRAINT chk_users_role") {
				t.Fatalf("runtime migrations must not contain destructive SQL: %q", statement)
			}
		}
	}
}

func TestConstraintStatementScopesConstraintToTable(t *testing.T) {
	statement := constraintStatement(
		"fk_assets_user",
		"users",
		`ALTER TABLE assets ADD CONSTRAINT fk_assets_user FOREIGN KEY (user_id) REFERENCES users(id)`,
	)

	if !strings.Contains(statement, "conrelid = 'users'::regclass") {
		t.Fatalf("expected constraint check to scope to table regclass, got %q", statement)
	}
}
