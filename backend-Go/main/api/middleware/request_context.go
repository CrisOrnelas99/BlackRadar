package middleware

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"

	appcontext "secureops/backend-go/api/context"
)

func RequestContext() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		transactionID := newTransactionID()
		logger := log.New(os.Stdout, fmt.Sprintf("transaction_id=%s ", transactionID), log.LstdFlags)

		appcontext.SetGinContext(ctx, appcontext.NewGinContext(ctx, transactionID, logger))
		logger.Printf("request started method=%s path=%s", ctx.Request.Method, ctx.Request.URL.Path)

		ctx.Next()

		logger.Printf("request completed status=%d", ctx.Writer.Status())
	}
}

func newTransactionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-0000-0000-000000000000"
	}

	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

