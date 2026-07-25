// Package controller provides HTTP handlers for AI diagnostic operations.
package controller

import (
	"net/http"
	"strings"

	basecontroller "blackradar/api/controller/shared"
	appcontext "blackradar/api/platform/requestcontext"
	promptservice "blackradar/api/service/prompt"
)

const maxTemporaryAIMessageLength = 1000

// AIController handles backend-only AI diagnostic HTTP requests.
type AIController struct {
	textAI promptservice.TextGenerationService
}

// NewAIController creates a new AIController.
func NewAIController(textAI promptservice.TextGenerationService) *AIController {
	return &AIController{textAI: textAI}
}

// TestProvider sends a fixed prompt to the configured AI provider.
func (c *AIController) TestProvider(ec *appcontext.GinContext) {
	if c.textAI == nil {
		basecontroller.HandleError(ec, http.StatusBadGateway, basecontroller.ErrUpstreamUnavailable, "AI provider test failed")
		return
	}

	response, err := c.textAI.GenerateText(ec.RequestContext(), promptservice.BuildDiagnosticRequest())
	if err != nil {
		basecontroller.HandleError(ec, http.StatusBadGateway, err, "AI provider test failed")
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
	if c.textAI == nil {
		basecontroller.HandleError(ec, http.StatusBadGateway, basecontroller.ErrUpstreamUnavailable, "AI message request failed")
		return
	}

	var request AIMessageRequest
	if handled := basecontroller.BindJSON(ec, &request); handled {
		return
	}

	message := strings.TrimSpace(request.Message)
	if message == "" || len(message) > maxTemporaryAIMessageLength {
		basecontroller.HandleError(ec, http.StatusBadRequest, basecontroller.ErrInvalidRequestBody, "Message must be between 1 and 1000 characters")
		return
	}

	response, err := c.textAI.GenerateText(ec.RequestContext(), promptservice.BuildTemporaryMessageRequest(message))
	if err != nil {
		basecontroller.HandleError(ec, http.StatusBadGateway, err, "AI message request failed")
		return
	}

	ec.JSON(http.StatusOK, AIMessageResponse{
		Provider:     "openai",
		ResponseText: response.Text,
		FinishReason: response.FinishReason,
	})
}
