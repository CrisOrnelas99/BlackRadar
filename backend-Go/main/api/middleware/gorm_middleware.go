package middleware

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	appcontext "secureops/backend-go/api/context"
)

func GormMiddleware(database *gorm.DB) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ec := appcontext.FromGinContext(ctx)
		ec.SetDatabase(database)
		ctx.Next()
	}
}

