package controller

import (
	"github.com/gin-gonic/gin"

	ratelimit "blackradar/api/middleware/rate_limit"
	appcontext "blackradar/api/platform/requestcontext"
)

// RegisterRoutes registers NVD lookup routes.
func RegisterRoutes(router *gin.RouterGroup, controller *NVDController) {
	nvd := router.Group("/nvd", ratelimit.NVDLookupRateLimit())
	nvd.GET("/cves/:cveId", appcontext.Wrap(controller.LookupCVE))
}
