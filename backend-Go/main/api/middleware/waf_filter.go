package middleware

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/model"
	"secureops/backend-go/api/repository"
)

func WafFilter(wafEventRepository *repository.WafEventRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		data := strings.ToLower(c.Request.URL.Path + " " + c.Request.URL.RawQuery)
		reason := ""

		switch {
		case strings.Contains(data, "../"):
			reason = "PATH_TRAVERSAL"
		case strings.Contains(data, "<script") || strings.Contains(data, "%3cscript"):
			reason = "XSS_PATTERN"
		case strings.Contains(data, "' or ") || strings.Contains(data, "%27%20or%20") || strings.Contains(data, "union select") || strings.Contains(data, "drop table"):
			reason = "SQLI_PATTERN"
		}

		if reason != "" {
			log.Printf("Blocked suspicious request: method=%s path=%s", c.Request.Method, c.Request.URL.Path)
			ec := appcontext.FromGinContext(c)
			wafEventRepository = repository.GetWafEventRepoFromEchoContext(ec)
			_ = wafEventRepository.Save(ec, model.WafEvent{
				Method:    c.Request.Method,
				Path:      c.Request.URL.Path,
				Reason:    reason,
				SourceIP:  c.ClientIP(),
				CreatedAt: time.Now(),
			})
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": ErrSuspiciousRequest.Message})
			return
		}

		c.Next()
	}
}
