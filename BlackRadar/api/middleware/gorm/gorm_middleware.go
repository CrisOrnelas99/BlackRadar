// Package gormmiddleware provides request-scoped GORM transaction middleware.
package gormmiddleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	appcontext "blackradar/api/context"
	middlewareerrors "blackradar/api/middleware"
)

// GormMiddleware opens one database transaction for the request and stores it on GinContext.
// Downstream repositories use the context database transparently; nested GORM Transaction calls
// become savepoints under this request transaction.
func GormMiddleware(database *gorm.DB) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if database == nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": middlewareerrors.ErrDatabaseUnavailable.Message})
			return
		}
		ec, err := appcontext.FromGinContext(ctx)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": middlewareerrors.ErrDatabaseUnavailable.Message})
			return
		}

		tx := database.WithContext(ctx.Request.Context()).Begin()
		if tx.Error != nil {
			ec.Logger().Error("database transaction begin failed", "error", tx.Error)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": middlewareerrors.ErrDatabaseTransactionFailed.Message})
			return
		}

		ec.SetDatabase(tx)
		defer finishRequestTransaction(ctx, ec, tx, database)

		ctx.Next()
	}
}

func finishRequestTransaction(ctx *gin.Context, ec *appcontext.GinContext, tx *gorm.DB, database *gorm.DB) {
	if recovered := recover(); recovered != nil {
		if err := tx.Rollback().Error; err != nil {
			ec.Logger().Error("database transaction rollback after panic failed", "error", err)
		}
		ec.SetDatabase(database)
		panic(recovered)
	}

	if shouldCommitRequestTransaction(ctx, tx) {
		if err := tx.Commit().Error; err != nil {
			ec.Logger().Error("database transaction commit failed", "error", err)
			if !ctx.Writer.Written() {
				ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": middlewareerrors.ErrDatabaseTransactionFailed.Message})
			}
		}
		ec.SetDatabase(database)
		return
	}

	if err := tx.Rollback().Error; err != nil {
		ec.Logger().Error("database transaction rollback failed", "error", err)
	}
	ec.SetDatabase(database)
}

func shouldCommitRequestTransaction(ctx *gin.Context, tx *gorm.DB) bool {
	if tx.Error != nil || len(ctx.Errors) > 0 {
		return false
	}

	status := ctx.Writer.Status()
	return status >= http.StatusOK && status <= http.StatusNonAuthoritativeInfo
}
