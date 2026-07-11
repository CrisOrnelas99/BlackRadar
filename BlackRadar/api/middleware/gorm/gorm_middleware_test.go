package gormmiddleware

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	appcontext "blackradar/api/context"
	contextmiddleware "blackradar/api/middleware/context"
)

func init() {
	sql.Register("blackradar_tx_test", transactionTrackingDriver{})
}

func TestGormMiddlewareCommitsSuccessfulRequestTransaction(t *testing.T) {
	database, closeDatabase := newTransactionTestDatabase(t)
	defer closeDatabase()

	router := gin.New()
	router.Use(contextmiddleware.RequestContext())
	router.Use(GormMiddleware(database))

	var requestDatabase *gorm.DB
	router.GET("/resource", func(ctx *gin.Context) {
		ec, err := appcontext.FromGinContext(ctx)
		if err != nil {
			t.Fatalf("expected request context, got %v", err)
		}
		requestDatabase = ec.Database()
		if requestDatabase == nil {
			t.Fatal("expected request transaction to be stored on GinContext")
		}
		if requestDatabase == database {
			t.Fatal("expected context database to be a request transaction, not the base database")
		}
		ctx.Status(http.StatusOK)
	})

	recorder := performRequest(router, http.MethodGet, "/resource")
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	assertTransactionStats(t, 1, 1, 0)
}

func TestGormMiddlewareRollsBackUnsuccessfulStatus(t *testing.T) {
	database, closeDatabase := newTransactionTestDatabase(t)
	defer closeDatabase()

	router := gin.New()
	router.Use(contextmiddleware.RequestContext())
	router.Use(GormMiddleware(database))
	router.POST("/resource", func(ctx *gin.Context) {
		ctx.Status(http.StatusBadRequest)
	})

	recorder := performRequest(router, http.MethodPost, "/resource")
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}
	assertTransactionStats(t, 1, 0, 1)
}

func TestGormMiddlewareRollsBackContextErrors(t *testing.T) {
	database, closeDatabase := newTransactionTestDatabase(t)
	defer closeDatabase()

	router := gin.New()
	router.Use(contextmiddleware.RequestContext())
	router.Use(GormMiddleware(database))
	router.POST("/resource", func(ctx *gin.Context) {
		_ = ctx.Error(errors.New("handler failed"))
		ctx.Status(http.StatusOK)
	})

	recorder := performRequest(router, http.MethodPost, "/resource")
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	assertTransactionStats(t, 1, 0, 1)
}

func TestGormMiddlewareRollsBackPanics(t *testing.T) {
	database, closeDatabase := newTransactionTestDatabase(t)
	defer closeDatabase()

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(contextmiddleware.RequestContext())
	router.Use(GormMiddleware(database))
	router.POST("/resource", func(ctx *gin.Context) {
		panic("boom")
	})

	recorder := performRequest(router, http.MethodPost, "/resource")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, recorder.Code)
	}
	assertTransactionStats(t, 1, 0, 1)
}

func TestGormMiddlewareRejectsMissingDatabase(t *testing.T) {
	router := gin.New()
	router.Use(contextmiddleware.RequestContext())
	router.Use(GormMiddleware(nil))
	router.GET("/resource", func(ctx *gin.Context) {
		t.Fatal("handler should not run when database is missing")
	})

	recorder := performRequest(router, http.MethodGet, "/resource")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, recorder.Code)
	}
}

func performRequest(router http.Handler, method string, target string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, target, nil)
	router.ServeHTTP(recorder, request)
	return recorder
}

type transactionCounters struct {
	mu        sync.Mutex
	begins    int
	commits   int
	rollbacks int
}

var testTransactionCounters transactionCounters

func resetTransactionStats() {
	testTransactionCounters.mu.Lock()
	defer testTransactionCounters.mu.Unlock()
	testTransactionCounters.begins = 0
	testTransactionCounters.commits = 0
	testTransactionCounters.rollbacks = 0
}

func assertTransactionStats(t *testing.T, begins int, commits int, rollbacks int) {
	t.Helper()
	testTransactionCounters.mu.Lock()
	defer testTransactionCounters.mu.Unlock()
	if testTransactionCounters.begins != begins || testTransactionCounters.commits != commits || testTransactionCounters.rollbacks != rollbacks {
		t.Fatalf("expected transaction stats begins=%d commits=%d rollbacks=%d, got begins=%d commits=%d rollbacks=%d", begins, commits, rollbacks, testTransactionCounters.begins, testTransactionCounters.commits, testTransactionCounters.rollbacks)
	}
}

func newTransactionTestDatabase(t *testing.T) (*gorm.DB, func()) {
	t.Helper()
	resetTransactionStats()

	sqlDatabase, err := sql.Open("blackradar_tx_test", "")
	if err != nil {
		t.Fatalf("failed to open transaction test database: %v", err)
	}

	database, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDatabase}), &gorm.Config{DisableAutomaticPing: true})
	if err != nil {
		_ = sqlDatabase.Close()
		t.Fatalf("failed to open gorm transaction test database: %v", err)
	}

	return database, func() {
		_ = sqlDatabase.Close()
	}
}

type transactionTrackingDriver struct{}

func (transactionTrackingDriver) Open(name string) (driver.Conn, error) {
	return transactionTrackingConn{}, nil
}

type transactionTrackingConn struct{}

func (transactionTrackingConn) Prepare(query string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not implemented for transaction middleware tests")
}

func (transactionTrackingConn) Close() error {
	return nil
}

func (transactionTrackingConn) Begin() (driver.Tx, error) {
	return transactionTrackingConn{}.BeginTx(context.Background(), driver.TxOptions{})
}

func (transactionTrackingConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	testTransactionCounters.mu.Lock()
	testTransactionCounters.begins++
	testTransactionCounters.mu.Unlock()
	return transactionTrackingTx{}, nil
}

type transactionTrackingTx struct{}

func (transactionTrackingTx) Commit() error {
	testTransactionCounters.mu.Lock()
	testTransactionCounters.commits++
	testTransactionCounters.mu.Unlock()
	return nil
}

func (transactionTrackingTx) Rollback() error {
	testTransactionCounters.mu.Lock()
	testTransactionCounters.rollbacks++
	testTransactionCounters.mu.Unlock()
	return nil
}
