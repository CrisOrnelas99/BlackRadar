// Package controller provides HTTP handlers for backend AI workflows.
package controller

import (
	"errors"
	"net/http"

	shared "blackradar/api/controller/shared"
	appcontext "blackradar/api/platform/requestcontext"
	aiservice "blackradar/api/service/ai"
)

// AIController handles backend-only AI HTTP requests.
type AIController struct {
	aiService aiservice.AIService
}

// NewAIController creates a new AIController.
func NewAIController(aiService aiservice.AIService) *AIController {
	return &AIController{aiService: aiService}
}

// GenerateDashboardSummary returns a grounded summary of the authenticated user's dashboard data.
func (c *AIController) GenerateDashboardSummary(ec *appcontext.GinContext) {
	if c.aiService == nil {
		shared.HandleError(ec, http.StatusBadGateway, shared.ErrUpstreamUnavailable, "Dashboard summary failed")
		return
	}

	summary, err := c.aiService.GenerateDashboardSummary(ec)
	if err != nil {
		if errors.Is(err, aiservice.ErrInvalidDashboardSummary) {
			shared.HandleError(ec, http.StatusBadGateway, err, "Dashboard summary was unavailable")
			return
		}
		shared.HandleError(ec, http.StatusBadGateway, err, "Dashboard summary failed")
		return
	}
	ec.JSON(http.StatusOK, ToAIDashboardSummaryResponse(summary))
}
