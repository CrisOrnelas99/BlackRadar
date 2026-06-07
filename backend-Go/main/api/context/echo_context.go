package context

import (
	stdcontext "context"
	"log"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const echoContextKey = "echoContext"

const (
	UserRepoKey             = "userRepo"
	AssetRepoKey            = "assetRepo"
	VulnerabilityRepoKey    = "vulnerabilityRepo"
	WafEventRepoKey         = "wafEventRepo"
	AuthServiceKey          = "authService"
	AssetServiceKey         = "assetService"
	AssetRiskServiceKey     = "assetRiskService"
	VulnerabilityServiceKey = "vulnerabilityService"
)

type EchoContext struct {
	*gin.Context
	transactionID string
	logger        *log.Logger
	database      *gorm.DB
}

func NewEchoContext(ctx *gin.Context, transactionID string, logger *log.Logger) *EchoContext {
	return &EchoContext{
		Context:       ctx,
		transactionID: transactionID,
		logger:        logger,
	}
}

func SetEchoContext(ctx *gin.Context, ec *EchoContext) {
	ctx.Set(echoContextKey, ec)
}

func FromGinContext(ctx *gin.Context) *EchoContext {
	value, exists := ctx.Get(echoContextKey)
	if !exists {
		return NewEchoContext(ctx, "", log.Default())
	}

	ec, ok := value.(*EchoContext)
	if !ok {
		return NewEchoContext(ctx, "", log.Default())
	}

	return ec
}

func Wrap(handler func(*EchoContext)) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		handler(FromGinContext(ctx))
	}
}

func (ec *EchoContext) UserID() string {
	username, exists := ec.Get("username")
	if !exists {
		return ""
	}

	value, ok := username.(string)
	if !ok {
		return ""
	}

	return value
}

func (ec *EchoContext) TransactionID() string {
	return ec.transactionID
}

func (ec *EchoContext) Logger() *log.Logger {
	return ec.logger
}

func (ec *EchoContext) Database() *gorm.DB {
	return ec.database
}

func (ec *EchoContext) SetDatabase(database *gorm.DB) {
	ec.database = database
}

func (ec *EchoContext) RequestContext() stdcontext.Context {
	return ec.Request.Context()
}
