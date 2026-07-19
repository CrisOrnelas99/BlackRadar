package db

import (
	"strings"
	"testing"
)

func TestSchemaStatementsDoNotAssignFallbackTenant(t *testing.T) {
	for _, statement := range schemaStatements() {
		if strings.Contains(statement, "admin_home") {
			t.Fatalf("expected schema statements to avoid fallback tenant assignment, found %q", statement)
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
