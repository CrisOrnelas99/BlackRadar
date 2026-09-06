/*
Package ai provides application services for backend-only AI workflows.
*/
package ai

import (
	"context"

	appcontext "blackradar/api/platform/requestcontext"
	textgenerationservice "blackradar/api/service/text_generation"
)

// AIService defines provider-backed backend AI workflows.
type AIService interface {
	/*
		TestProvider sends the fixed diagnostic request to the configured provider.

		Implementations must use a backend-owned prompt and return a dependency
		error when the provider is unavailable or not configured.
	*/
	TestProvider(ctx context.Context) (textgenerationservice.TextGenerationResponse, error)

	/*
		GenerateDashboardSummary builds a read-only snapshot from the authenticated
		user's authorized dashboard data and returns a provider-generated explanation.

		Implementations must obtain identity and organization scope from ec, use
		bounded repository reads, and preserve the backend-owned prompt boundary.
		The result is advisory and must not perform database writes or accept
		browser-supplied dashboard records. Provider, persistence, authentication,
		and invalid-model-output failures must be returned to the controller for
		safe translation.
	*/
	GenerateDashboardSummary(ec *appcontext.GinContext) (DashboardSummary, error)
}
