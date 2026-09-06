# 🤖 Dashboard AI Summary

## Overview

BlackRadar includes a backend-owned AI summary for the dashboard. The feature turns the authenticated user's current asset and vulnerability posture into a short, grounded explanation that appears in the dashboard UI.

The browser can request the summary and render it, but it does not decide what data is included, what the model may see, or whether the result is trustworthy.

## Purpose

The dashboard summary gives users a concise explanation of what is most urgent, what looks stable, and what should be verified next. It is meant to complement the dashboard counts and charts, not replace them.

## Current Behavior

The current implementation is exposed through `POST /api/dashboard/ai-summary`.

The UI uses the dashboard page's AI card to request the summary on demand and can keep a cached result for the current session user. The card is independent from the dashboard overview request so the summary action stays available even if the metrics request fails.

The backend workflow:

1. Reads the authenticated user from request context.
2. Loads a bounded dashboard snapshot from backend repositories.
3. Redacts real identifiers before anything reaches the provider.
4. Builds a locked text-generation prompt in backend code.
5. Calls the OpenAI client through the backend provider boundary.
6. Accepts only strict JSON output that matches the expected schema.
7. Restores real asset and vulnerability identifiers only after validation succeeds.

The returned summary includes:

- a headline
- an overall assessment
- a short summary
- priority findings tied to known dashboard evidence
- positive observations
- uncertainties to verify

## Security Boundary

The dashboard AI workflow follows the same backend trust-boundary rules as the rest of BlackRadar:

- the browser never supplies provider credentials
- the browser never decides which records may be summarized
- the backend controls prompt content and response validation
- provider output is treated as untrusted until validated
- failed refresh, authorization, and provider errors are handled separately from normal dashboard rendering

See [security-boundaries.md](security-boundaries.md) for the shared trust model and [frontend-angular.md](frontend-angular.md) for the browser boundary.

## Current Limitations

- The summary is read-only.
- The summary is only as complete as the bounded snapshot the backend assembles.
- OpenAI is used as an advisory explanation layer, not a source of truth for risk.
- The feature does not write remediation actions, alerts, or workflow items yet.

## Key Terms

- **Dashboard summary:** The validated AI explanation returned for the current dashboard state.
- **Bounded snapshot:** A limited, backend-selected set of counts and evidence sent to the model.
- **Locked prompt:** A backend-owned prompt that cannot be changed by the browser.
