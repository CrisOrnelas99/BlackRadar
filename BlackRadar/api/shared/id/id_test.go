package id

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestNewRandomID(t *testing.T) {
	id := NewRandomID()

	if id == "" || len(id) != 36 {
		t.Fatalf("expected UUID random id, got %q", id)
	}
}

func TestIsPrimaryKeyViolation(t *testing.T) {
	pkErr := &pgconn.PgError{Code: "23505", ConstraintName: "assets_pkey"}
	uniqueButNotPkErr := &pgconn.PgError{Code: "23505", ConstraintName: "idx_assets_user_id"}

	if !IsPrimaryKeyViolation(pkErr) {
		t.Fatal("expected primary key violation to return true")
	}
	if IsPrimaryKeyViolation(uniqueButNotPkErr) {
		t.Fatal("expected non-primary-key unique violation to return false")
	}
	if IsPrimaryKeyViolation(errors.New("plain error")) {
		t.Fatal("expected plain error to return false")
	}
}
