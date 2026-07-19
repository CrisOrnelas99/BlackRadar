package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"blackradar/api/platform/config"
)

func init() {
	sql.Register("blackradar_transaction_helper_test", transactionHelperDriver{})
}

func TestConnectRejectsMissingDatabaseURL(t *testing.T) {
	_, err := Connect(context.Background(), config.Config{})
	if err == nil {
		t.Fatal("expected missing database URL to fail")
	}

	if !strings.Contains(err.Error(), "database URL is required") {
		t.Fatalf("expected database URL validation error, got %v", err)
	}
}

func TestCloseAcceptsNilDatabase(t *testing.T) {
	if err := Close(nil); err != nil {
		t.Fatalf("expected nil database close to succeed, got %v", err)
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
		{name: "nil", input: nil, expectSame: nil},
		{name: "foreign key violation", input: foreignKeyErr, expectIs: ErrForeignKeyViolation},
		{name: "wrapped foreign key violation", input: fmt.Errorf("insert asset vulnerability: %w", foreignKeyErr), expectIs: ErrForeignKeyViolation},
		{name: "check constraint violation", input: checkConstraintErr, expectIs: ErrCheckConstraintViolation},
		{name: "unique violation", input: uniqueErr, expectIs: ErrUniqueViolation},
		{name: "unknown postgres error", input: unknownPgErr, expectSame: unknownPgErr},
		{name: "plain error", input: plainErr, expectSame: plainErr},
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

func TestWithinTransactionRejectsMissingDatabase(t *testing.T) {
	err := WithinTransaction(context.Background(), nil, func(tx *gorm.DB) error {
		return nil
	})

	if err == nil || !strings.Contains(err.Error(), "database is required") {
		t.Fatalf("expected missing database error, got %v", err)
	}
}

func TestWithinTransactionRejectsMissingOperation(t *testing.T) {
	database, closeDatabase := newTransactionHelperTestDatabase(t)
	defer closeDatabase()

	err := WithinTransaction(context.Background(), database, nil)

	if err == nil || !strings.Contains(err.Error(), "operation is required") {
		t.Fatalf("expected missing operation error, got %v", err)
	}
}

func TestWithinTransactionCommitsSuccessfulOperation(t *testing.T) {
	database, closeDatabase := newTransactionHelperTestDatabase(t)
	defer closeDatabase()

	err := WithinTransaction(context.Background(), database, func(tx *gorm.DB) error {
		if tx == nil {
			t.Fatal("expected transaction database")
		}
		return nil
	})

	if err != nil {
		t.Fatalf("expected transaction to commit, got %v", err)
	}
	assertHelperTransactionStats(t, 1, 1, 0)
}

func TestWithinTransactionRollsBackFailedOperation(t *testing.T) {
	database, closeDatabase := newTransactionHelperTestDatabase(t)
	defer closeDatabase()

	operationErr := errors.New("operation failed")
	err := WithinTransaction(context.Background(), database, func(tx *gorm.DB) error {
		return operationErr
	})

	if !errors.Is(err, operationErr) {
		t.Fatalf("expected operation error to be wrapped, got %v", err)
	}
	assertHelperTransactionStats(t, 1, 0, 1)
}

type helperTransactionCounters struct {
	mu        sync.Mutex
	begins    int
	commits   int
	rollbacks int
}

var testHelperTransactionCounters helperTransactionCounters

func resetHelperTransactionStats() {
	testHelperTransactionCounters.mu.Lock()
	defer testHelperTransactionCounters.mu.Unlock()
	testHelperTransactionCounters.begins = 0
	testHelperTransactionCounters.commits = 0
	testHelperTransactionCounters.rollbacks = 0
}

func assertHelperTransactionStats(t *testing.T, begins int, commits int, rollbacks int) {
	t.Helper()
	testHelperTransactionCounters.mu.Lock()
	defer testHelperTransactionCounters.mu.Unlock()
	if testHelperTransactionCounters.begins != begins ||
		testHelperTransactionCounters.commits != commits ||
		testHelperTransactionCounters.rollbacks != rollbacks {
		t.Fatalf(
			"expected transaction stats begins=%d commits=%d rollbacks=%d, got begins=%d commits=%d rollbacks=%d",
			begins,
			commits,
			rollbacks,
			testHelperTransactionCounters.begins,
			testHelperTransactionCounters.commits,
			testHelperTransactionCounters.rollbacks,
		)
	}
}

func newTransactionHelperTestDatabase(t *testing.T) (*gorm.DB, func()) {
	t.Helper()
	resetHelperTransactionStats()

	sqlDatabase, err := sql.Open("blackradar_transaction_helper_test", "")
	if err != nil {
		t.Fatalf("failed to open transaction helper test database: %v", err)
	}

	database, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDatabase}), &gorm.Config{DisableAutomaticPing: true})
	if err != nil {
		_ = sqlDatabase.Close()
		t.Fatalf("failed to open gorm transaction helper test database: %v", err)
	}

	return database, func() {
		_ = sqlDatabase.Close()
	}
}

type transactionHelperDriver struct{}

func (transactionHelperDriver) Open(name string) (driver.Conn, error) {
	return transactionHelperConn{}, nil
}

type transactionHelperConn struct{}

func (transactionHelperConn) Prepare(query string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not implemented for transaction helper tests")
}

func (transactionHelperConn) Close() error {
	return nil
}

func (transactionHelperConn) Begin() (driver.Tx, error) {
	return transactionHelperConn{}.BeginTx(context.Background(), driver.TxOptions{})
}

func (transactionHelperConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	testHelperTransactionCounters.mu.Lock()
	testHelperTransactionCounters.begins++
	testHelperTransactionCounters.mu.Unlock()
	return transactionHelperTx{}, nil
}

type transactionHelperTx struct{}

func (transactionHelperTx) Commit() error {
	testHelperTransactionCounters.mu.Lock()
	testHelperTransactionCounters.commits++
	testHelperTransactionCounters.mu.Unlock()
	return nil
}

func (transactionHelperTx) Rollback() error {
	testHelperTransactionCounters.mu.Lock()
	testHelperTransactionCounters.rollbacks++
	testHelperTransactionCounters.mu.Unlock()
	return nil
}
