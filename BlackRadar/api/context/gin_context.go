/*
	Package context defines the request-scoped application context used by middleware,
	controllers, services, and repositories. It holds per-request metadata, logging,
	database access, and authenticated request state.
*/

package requestcontext

import (
	stdcontext "context"
	"log/slog"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	ginContextKey     = "ginContext"
	userIDKey         = "userID"
	usernameKey       = "username"
	userRoleKey       = "userRole"
	organizationIDKey = "organizationID"
)

type GinContext struct {
	*gin.Context
	transactionID string
	logger        *slog.Logger
	database      *gorm.DB
}

// NewGinContext creates a new request-scoped GinContext wrapper.
func NewGinContext(ctx *gin.Context, transactionID string, logger *slog.Logger) *GinContext {
	return &GinContext{
		Context:       ctx,
		transactionID: transactionID,
		logger:        logger,
	}
}

// SetGinContext stores the request-scoped GinContext wrapper on the raw Gin context.
func SetGinContext(ctx *gin.Context, ec *GinContext) {
	ctx.Set(ginContextKey, ec)
}

// FromGinContext returns the request-scoped GinContext wrapper if present,
// otherwise it returns a safe fallback wrapper around the current Gin context.
func FromGinContext(ctx *gin.Context) *GinContext {
	value, exists := ctx.Get(ginContextKey)
	if !exists {
		return NewGinContext(ctx, "", slog.Default())
	}

	ec, ok := value.(*GinContext)
	if !ok {
		return NewGinContext(ctx, "", slog.Default())
	}

	return ec
}

// Wrap converts a handler that expects *GinContext into a standard Gin middleware.
func Wrap(handler func(*GinContext)) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		handler(FromGinContext(ctx))
	}
}

// UserID returns the authenticated user ID stored in the request context.
func (ec *GinContext) UserID() string {
	userID, exists := ec.Get(userIDKey)
	if !exists {
		return ""
	}

	value, ok := userID.(string)
	if !ok {
		return ""
	}

	return value
}

// Username returns the authenticated username stored in the request context.
func (ec *GinContext) Username() string {
	username, exists := ec.Get(usernameKey)
	if !exists {
		return ""
	}

	value, ok := username.(string)
	if !ok {
		return ""
	}

	return value
}

// UserRole returns the authenticated role stored in the request context.
func (ec *GinContext) UserRole() string {
	role, exists := ec.Get(userRoleKey)
	if !exists {
		return ""
	}

	value, ok := role.(string)
	if !ok {
		return ""
	}

	return value
}

// OrganizationID returns the authenticated organization ID stored in the request context.
func (ec *GinContext) OrganizationID() string {
	organizationID, exists := ec.Get(organizationIDKey)
	if !exists {
		return ""
	}

	value, ok := organizationID.(string)
	if !ok {
		return ""
	}

	return value
}

// SetUserID stores the authenticated user ID on the request context.
func (ec *GinContext) SetUserID(userID string) {
	ec.Set(userIDKey, userID)
}

// SetUsername stores the authenticated username on the request context.
func (ec *GinContext) SetUsername(username string) {
	ec.Set(usernameKey, username)
}

// SetUserRole stores the authenticated role on the request context.
func (ec *GinContext) SetUserRole(role string) {
	ec.Set(userRoleKey, role)
}

// SetOrganizationID stores the authenticated organization ID on the request context.
func (ec *GinContext) SetOrganizationID(organizationID string) {
	ec.Set(organizationIDKey, organizationID)
}

// TransactionID returns the request trace identifier.
func (ec *GinContext) TransactionID() string {
	return ec.transactionID
}

// Logger returns the request-scoped logger.
func (ec *GinContext) Logger() *slog.Logger {
	if ec.logger == nil {
		return slog.Default()
	}
	return ec.logger
}

// Database returns the request-scoped database connection.
func (ec *GinContext) Database() *gorm.DB {
	return ec.database
}

// SetDatabase stores the request-scoped database connection.
func (ec *GinContext) SetDatabase(database *gorm.DB) {
	ec.database = database
}

// RequestContext returns the underlying request context from Gin.
func (ec *GinContext) RequestContext() stdcontext.Context {
	return ec.Request.Context()
}
