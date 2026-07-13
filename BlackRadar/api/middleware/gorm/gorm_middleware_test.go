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

	requestcontext "blackradar/api/context"
	contextmiddleware "blackradar/api/middleware/context"
)

func init() {
	sql.Register("blackradar_request_database_test", transactionTrackingDriver{})
}

func TestRequestDatabaseStoresContextualDatabaseWithoutTransaction(t *testing.T) {
	database, closeDatabase := newRequestDatabaseTestDatabase(t)
	defer closeDatabase()

	router := gin.New()
	router.Use(contextmiddleware.RequestContext(nil, nil))
	router.Use(RequestDatabase(database))

	var appContext *requestcontext.GinContext
	router.GET("/resource", func(ctx *gin.Context) {
		var err error
		appContext, err = requestcontext.FromGinContext(ctx)
		if err != nil {
			t.Fatalf("expected request context, got %v", err)
		}

		requestDatabase := appContext.Database()
		if requestDatabase == nil {
			t.Fatal("expected request database to be stored on GinContext")
		}
		if requestDatabase == database {
			t.Fatal("expected context database to be request-scoped, not the base database")
		}

		ctx.Status(http.StatusOK)
	})

	recorder := performRequest(router, http.MethodGet, "/resource")
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if appContext.Database() != nil {
		t.Fatal("expected request database to be cleared after request")
	}
	assertTransactionStats(t, 0, 0, 0)
}

func TestGormMiddlewareCompatibilityWrapperUsesRequestDatabase(t *testing.T) {
	database, closeDatabase := newRequestDatabaseTestDatabase(t)
	defer closeDatabase()

	router := gin.New()
	router.Use(contextmiddleware.RequestContext(nil, nil))
	router.Use(GormMiddleware(database))
	router.GET("/resource", func(ctx *gin.Context) {
		appContext, err := requestcontext.FromGinContext(ctx)
		if err != nil {
			t.Fatalf("expected request context, got %v", err)
		}
		if appContext.Database() == nil {
			t.Fatal("expected request database")
		}
		ctx.Status(http.StatusNoContent)
	})

	recorder := performRequest(router, http.MethodGet, "/resource")
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, recorder.Code)
	}
	assertTransactionStats(t, 0, 0, 0)
}

func TestRequestDatabaseRejectsMissingDatabase(t *testing.T) {
	router := gin.New()
	router.Use(contextmiddleware.RequestContext(nil, nil))
	router.Use(RequestDatabase(nil))
	router.GET("/resource", func(ctx *gin.Context) {
		t.Fatal("handler should not run when database is missing")
	})

	recorder := performRequest(router, http.MethodGet, "/resource")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, recorder.Code)
	}
}

func TestRequestDatabaseRejectsMissingRequestContext(t *testing.T) {
	database, closeDatabase := newRequestDatabaseTestDatabase(t)
	defer closeDatabase()

	router := gin.New()
	router.Use(RequestDatabase(database))
	router.GET("/resource", func(ctx *gin.Context) {
		t.Fatal("handler should not run when request context is missing")
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
	if testTransactionCounters.begins != begins ||
		testTransactionCounters.commits != commits ||
		testTransactionCounters.rollbacks != rollbacks {
		t.Fatalf(
			"expected transaction stats begins=%d commits=%d rollbacks=%d, got begins=%d commits=%d rollbacks=%d",
			begins,
			commits,
			rollbacks,
			testTransactionCounters.begins,
			testTransactionCounters.commits,
			testTransactionCounters.rollbacks,
		)
	}
}

func newRequestDatabaseTestDatabase(t *testing.T) (*gorm.DB, func()) {
	t.Helper()
	resetTransactionStats()

	sqlDatabase, err := sql.Open("blackradar_request_database_test", "")
	if err != nil {
		t.Fatalf("failed to open request database test database: %v", err)
	}

	database, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDatabase}), &gorm.Config{DisableAutomaticPing: true})
	if err != nil {
		_ = sqlDatabase.Close()
		t.Fatalf("failed to open gorm request database test database: %v", err)
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
	return nil, errors.New("prepare is not implemented for request database middleware tests")
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
