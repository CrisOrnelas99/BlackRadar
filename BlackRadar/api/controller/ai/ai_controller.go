// Package controller provides HTTP handlers for AI diagnostic operations.
package controller

import (
	"errors"
	"net/http"

	shared "blackradar/api/controller/shared"
	appcontext "blackradar/api/platform/requestcontext"
	aiservice "blackradar/api/service/ai"
)

// AIController handles backend-only AI diagnostic HTTP requests.
type AIController struct {
	aiService aiservice.AIService
}

// NewAIController creates a new AIController.
func NewAIController(aiService aiservice.AIService) *AIController {
	return &AIController{aiService: aiService}
}

// TestProvider sends a fixed prompt to the configured AI provider.
func (c *AIController) TestProvider(ec *appcontext.GinContext) {
	if c.aiService == nil {
		shared.HandleError(ec, http.StatusBadGateway, shared.ErrUpstreamUnavailable, "AI provider test failed")
		return
	}

	response, err := c.aiService.TestProvider(ec.RequestContext())
	if err != nil {
		shared.HandleError(ec, http.StatusBadGateway, err, "AI provider test failed")
		return
	}

	ec.JSON(http.StatusOK, AITestResponse{
		Status:       "ok",
		Provider:     "openai",
		ResponseText: response.Text,
		FinishReason: response.FinishReason,
	})
}

// SendMessage sends a temporary admin-only diagnostic message to the configured AI provider.
func (c *AIController) SendMessage(ec *appcontext.GinContext) {
	var request AIMessageRequest
	if handled := shared.BindJSON(ec, &request); handled {
		return
	}
	if c.aiService == nil {
		shared.HandleError(ec, http.StatusBadGateway, shared.ErrUpstreamUnavailable, "AI message request failed")
		return
	}

	response, err := c.aiService.SendMessage(ec.RequestContext(), request.Message)
	if err != nil {
		if errors.Is(err, aiservice.ErrInvalidAIMessage) {
			shared.HandleError(ec, http.StatusBadRequest, err, err.Error())
			return
		}
		shared.HandleError(ec, http.StatusBadGateway, err, "AI message request failed")
		return
	}

	ec.JSON(http.StatusOK, AIMessageResponse{
		Provider:     "openai",
		ResponseText: response.Text,
		FinishReason: response.FinishReason,
	})
}
