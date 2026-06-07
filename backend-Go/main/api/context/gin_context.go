package context

import (
	stdcontext "context"
	"log"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const ginContextKey = "ginContext"

type GinContext struct {
	*gin.Context
	transactionID string
	logger        *log.Logger
	database      *gorm.DB
}

func NewGinContext(ctx *gin.Context, transactionID string, logger *log.Logger) *GinContext {
	return &GinContext{
		Context:       ctx,
		transactionID: transactionID,
		logger:        logger,
	}
}

func SetGinContext(ctx *gin.Context, ec *GinContext) {
	ctx.Set(ginContextKey, ec)
}

func FromGinContext(ctx *gin.Context) *GinContext {
	value, exists := ctx.Get(ginContextKey)
	if !exists {
		return NewGinContext(ctx, "", log.Default())
	}

	ec, ok := value.(*GinContext)
	if !ok {
		return NewGinContext(ctx, "", log.Default())
	}

	return ec
}

func Wrap(handler func(*GinContext)) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		handler(FromGinContext(ctx))
	}
}

func (ec *GinContext) UserID() int64 {
	userID, exists := ec.Get("userID")
	if !exists {
		return 0
	}

	value, ok := userID.(int64)
	if !ok {
		return 0
	}

	return value
}

func (ec *GinContext) Username() string {
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

func (ec *GinContext) TransactionID() string {
	return ec.transactionID
}

func (ec *GinContext) Logger() *log.Logger {
	return ec.logger
}

func (ec *GinContext) Database() *gorm.DB {
	return ec.database
}

func (ec *GinContext) SetDatabase(database *gorm.DB) {
	ec.database = database
}

func (ec *GinContext) RequestContext() stdcontext.Context {
	return ec.Request.Context()
}
