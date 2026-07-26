// Package controller provides HTTP handlers for AI diagnostic operations.
package controller

import (
	"net/http"
	"strings"

	shared "blackradar/api/controller/shared"
	openaiexternal "blackradar/api/external/openai"
	appcontext "blackradar/api/platform/requestcontext"
	textgenerationservice "blackradar/api/service/text_generation"
)

const maxTemporaryAIMessageLength = 1000

// AIController handles backend-only AI diagnostic HTTP requests.
type AIController struct {
	textAI openaiexternal.OpenAIClientInterface
}

// NewAIController creates a new AIController.
func NewAIController(textAI openaiexternal.OpenAIClientInterface) *AIController {
	return &AIController{textAI: textAI}
}

// TestProvider sends a fixed prompt to the configured AI provider.
func (c *AIController) TestProvider(ec *appcontext.GinContext) {
	if c.textAI == nil {
		shared.HandleError(ec, http.StatusBadGateway, shared.ErrUpstreamUnavailable, "AI provider test failed")
		return
	}

	response, err := c.textAI.GenerateText(ec.RequestContext(), textgenerationservice.BuildDiagnosticRequest())
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
	if c.textAI == nil {
		shared.HandleError(ec, http.StatusBadGateway, shared.ErrUpstreamUnavailable, "AI message request failed")
		return
	}

	var request AIMessageRequest
	if handled := shared.BindJSON(ec, &request); handled {
		return
	}

	message := strings.TrimSpace(request.Message)
	if message == "" || len(message) > maxTemporaryAIMessageLength {
		shared.HandleError(ec, http.StatusBadRequest, shared.ErrInvalidRequestBody, "Message must be between 1 and 1000 characters")
		return
	}

	response, err := c.textAI.GenerateText(ec.RequestContext(), textgenerationservice.BuildTemporaryMessageRequest(message))
	if err != nil {
		shared.HandleError(ec, http.StatusBadGateway, err, "AI message request failed")
		return
	}

	ec.JSON(http.StatusOK, AIMessageResponse{
		Provider:     "openai",
		ResponseText: response.Text,
		FinishReason: response.FinishReason,
	})
}
