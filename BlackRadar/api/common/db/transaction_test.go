package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func init() {
	sql.Register("blackradar_transaction_helper_test", transactionHelperDriver{})
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
