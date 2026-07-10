package utils

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestNewRandomID(t *testing.T) {
	id := NewRandomID()

	if id == "" || len(id) != 36 {
		t.Fatalf("expected UUID random id, got %q", id)
	}
}

func TestNewTokenID(t *testing.T) {
	tokenID := NewTokenID()

	if len(tokenID) != 32 {
		t.Fatalf("expected 32 hex characters, got %d", len(tokenID))
	}
	if tokenID == "00000000000000000000000000000000" {
		t.Fatal("expected token id to be random, got fallback value")
	}
}

func TestDBErrorMessage(t *testing.T) {
	err := DBError{Message: "database failed"}

	if err.Error() != "database failed" {
		t.Fatalf("expected database failed, got %q", err.Error())
	}
}

func TestTranslateDatabaseError(t *testing.T) {
	foreignKeyErr := &pgconn.PgError{Code: "23503", Message: "foreign key violation"}
	checkConstraintErr := &pgconn.PgError{Code: "23514", Message: "check constraint violation"}
	uniqueErr := &pgconn.PgError{Code: "23505", Message: "unique violation"}
	unknownPgErr := &pgconn.PgError{Code: "22001", Message: "value too long"}
	plainErr := errors.New("plain database error")

	tests := []struct {
		name       string
		input      error
		expectSame error
		expectIs   error
	}{
		{
			name:       "nil",
			input:      nil,
			expectSame: nil,
		},
		{
			name:     "foreign key violation",
			input:    foreignKeyErr,
			expectIs: ErrForeignKeyViolation,
		},
		{
			name:     "wrapped foreign key violation",
			input:    fmt.Errorf("insert asset vulnerability: %w", foreignKeyErr),
			expectIs: ErrForeignKeyViolation,
		},
		{
			name:     "check constraint violation",
			input:    checkConstraintErr,
			expectIs: ErrCheckConstraintViolation,
		},
		{
			name:     "unique violation",
			input:    uniqueErr,
			expectIs: ErrUniqueViolation,
		},
		{
			name:       "unknown postgres error",
			input:      unknownPgErr,
			expectSame: unknownPgErr,
		},
		{
			name:       "plain error",
			input:      plainErr,
			expectSame: plainErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := TranslateDatabaseError(tt.input)

			if tt.expectSame != nil || tt.input == nil {
				if actual != tt.expectSame {
					t.Fatalf("expected same error %v, got %v", tt.expectSame, actual)
				}
			}

			if tt.expectIs != nil {
				if !errors.Is(actual, tt.expectIs) {
					t.Fatalf("expected translated error to match %v, got %v", tt.expectIs, actual)
				}
				if !errors.Is(actual, tt.input) {
					t.Fatalf("expected translated error to wrap original error %v, got %v", tt.input, actual)
				}
			}
		})
	}
}

func TestIsPostgresError(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "23505", Message: "unique violation"}

	if !isPostgresError(pgErr, "23505") {
		t.Fatal("expected matching postgres error code")
	}
	if !isPostgresError(fmt.Errorf("wrapped: %w", pgErr), "23505") {
		t.Fatal("expected wrapped postgres error code to match")
	}
	if isPostgresError(pgErr, "23503") {
		t.Fatal("expected non-matching postgres error code to return false")
	}
	if isPostgresError(errors.New("plain error"), "23505") {
		t.Fatal("expected plain error to return false")
	}
	if isPostgresError(nil, "23505") {
		t.Fatal("expected nil error to return false")
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
