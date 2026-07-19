// Package requestcontext provides request-scoped dependencies and authenticated
// identity for Gin handlers.
package requestcontext

import (
	stdcontext "context"
	"errors"
	"log/slog"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const ginContextKey = "blackradar.requestcontext"

var (
	ErrContextNotInitialized = errors.New("request context has not been initialized")
	ErrPrincipalNotSet       = errors.New("authenticated principal has not been set")
	ErrInvalidPrincipal      = errors.New("authenticated principal is invalid")
	ErrUsernameNotSet        = errors.New("authenticated principal username has not been set")
	ErrRoleNotSet            = errors.New("authenticated principal role has not been set")
)

// Principal contains identity information established by authentication
// middleware.
//
// Values in Principal must come from trusted authentication data or verified
// database records, never directly from request parameters.
type Principal struct {
	UserID         string
	Username       string
	Role           string
	OrganizationID string
}

// Validate ensures the fields required for authorization and tenant isolation
// are present.
func (principal Principal) Validate() error {
	if strings.TrimSpace(principal.UserID) == "" {
		return ErrInvalidPrincipal
	}
	if strings.TrimSpace(principal.OrganizationID) == "" {
		return ErrInvalidPrincipal
	}

	return nil
}

type GinContext struct {
	*gin.Context
	requestID       string
	logger          *slog.Logger
	databaseSession *gorm.DB
	principal       *Principal
}

// NewGinContext creates a new request-scoped GinContext wrapper.
func NewGinContext(ctx *gin.Context, requestID string, logger *slog.Logger) *GinContext {
	return &GinContext{
		Context:   ctx,
		requestID: requestID,
		logger:    logger,
	}
}

// SetGinContext stores the request-scoped GinContext wrapper on the raw Gin
// context.
func SetGinContext(ctx *gin.Context, ec *GinContext) {
	ctx.Set(ginContextKey, ec)
}

// FromGinContext returns the initialized request-scoped GinContext wrapper.
func FromGinContext(ctx *gin.Context) (*GinContext, error) {
	value, exists := ctx.Get(ginContextKey)
	if !exists {
		return nil, ErrContextNotInitialized
	}

	ec, ok := value.(*GinContext)
	if !ok || ec == nil {
		return nil, ErrContextNotInitialized
	}

	return ec, nil
}

// Wrap converts a handler that expects *GinContext into a standard Gin handler.
func Wrap(handler func(*GinContext)) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ec, err := FromGinContext(ctx)
		if err != nil {
			ctx.AbortWithStatus(500)
			return
		}

		handler(ec)
	}
}

// SetPrincipal stores validated authenticated identity on the request context.
func (ec *GinContext) SetPrincipal(principal Principal) error {
	principal.UserID = strings.TrimSpace(principal.UserID)
	principal.Username = strings.TrimSpace(principal.Username)
	principal.Role = strings.TrimSpace(principal.Role)
	principal.OrganizationID = strings.TrimSpace(principal.OrganizationID)

	if err := principal.Validate(); err != nil {
		return err
	}

	principalCopy := principal
	ec.principal = &principalCopy

	return nil
}

// SetUserID updates the principal user ID on the request context.
func (ec *GinContext) SetUserID(userID string) {
	principal := ec.partialPrincipal()
	principal.UserID = strings.TrimSpace(userID)
	ec.principal = &principal
}

// SetUsername updates the principal username on the request context.
func (ec *GinContext) SetUsername(username string) {
	principal := ec.partialPrincipal()
	principal.Username = strings.TrimSpace(username)
	ec.principal = &principal
}

// SetUserRole updates the principal role on the request context.
func (ec *GinContext) SetUserRole(role string) {
	principal := ec.partialPrincipal()
	principal.Role = strings.TrimSpace(role)
	ec.principal = &principal
}

// SetOrganizationID updates the principal organization ID on the request
// context.
func (ec *GinContext) SetOrganizationID(organizationID string) {
	principal := ec.partialPrincipal()
	principal.OrganizationID = strings.TrimSpace(organizationID)
	ec.principal = &principal
}

// Principal returns the validated authenticated principal.
func (ec *GinContext) Principal() (Principal, error) {
	if ec == nil {
		return Principal{}, ErrContextNotInitialized
	}
	if ec.principal == nil {
		return Principal{}, ErrPrincipalNotSet
	}
	if err := ec.principal.Validate(); err != nil {
		return Principal{}, err
	}

	return *ec.principal, nil
}

// UserID returns the authenticated user ID.
func (ec *GinContext) UserID() (string, error) {
	principal, err := ec.Principal()
	if err != nil {
		return "", err
	}

	return principal.UserID, nil
}

// Username returns the authenticated username.
func (ec *GinContext) Username() (string, error) {
	principal, err := ec.Principal()
	if err != nil {
		return "", err
	}
	if principal.Username == "" {
		return "", ErrUsernameNotSet
	}

	return principal.Username, nil
}

// UserRole returns the authenticated role.
func (ec *GinContext) UserRole() (string, error) {
	principal, err := ec.Principal()
	if err != nil {
		return "", err
	}
	if principal.Role == "" {
		return "", ErrRoleNotSet
	}

	return principal.Role, nil
}

// OrganizationID returns the authenticated organization ID.
func (ec *GinContext) OrganizationID() (string, error) {
	principal, err := ec.Principal()
	if err != nil {
		return "", err
	}

	return principal.OrganizationID, nil
}

// RequestID returns the request trace identifier.
func (ec *GinContext) RequestID() string {
	if ec == nil {
		return ""
	}

	return ec.requestID
}

// Logger returns the request-scoped logger.
func (ec *GinContext) Logger() *slog.Logger {
	if ec == nil || ec.logger == nil {
		return slog.Default()
	}
	return ec.logger
}

// Database returns the request-scoped database session.
func (ec *GinContext) Database() *gorm.DB {
	if ec == nil {
		return nil
	}
	return ec.databaseSession
}

// SetDatabase stores the request-scoped database session.
func (ec *GinContext) SetDatabase(database *gorm.DB) {
	ec.databaseSession = database
}

// RequestContext returns the underlying request context from Gin.
func (ec *GinContext) RequestContext() stdcontext.Context {
	return ec.Request.Context()
}

func (ec *GinContext) partialPrincipal() Principal {
	if ec == nil || ec.principal == nil {
		return Principal{}
	}

	return *ec.principal
}
