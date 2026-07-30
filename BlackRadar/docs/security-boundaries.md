# Security Boundaries

## Overview

BlackRadar treats the backend as the primary trust boundary. The browser is a client of the system, not an authority over identity, ownership, permissions, risk, or external integrations.

This document defines the shared security model used by the feature documents. Feature-specific workflows should refer here instead of repeating these rules.

## Trust Model

Trusted decisions are made from server-side state:

- authenticated principal and session state
- backend authorization checks
- database ownership predicates
- validated domain data
- bounded, backend-controlled external results

Browser input, imported text, AI output, NVD responses, and route parameters are untrusted until validated at the relevant boundary.

## Request Flow

```text
Browser
  -> Angular UX and API client
  -> Gin controller
  -> service business rules
  -> repository persistence
  -> PostgreSQL
```

Controllers bind requests and map responses. Services enforce ownership, validation, authorization, and workflow rules. Repositories perform scoped persistence. Middleware establishes authentication, request context, and database sessions.

## Ownership

Current ownership is user-scoped. The authenticated user ID comes from the server-side principal; it is never accepted as authoritative request data.

Alice must not be able to access Bob's asset, vulnerability, or relationship by guessing an identifier. Queries therefore scope the relevant record by both its identifier and Alice's authenticated user ID.

Organization tenancy is planned and must not be implied by the current implementation.

## External Integrations

NVD and OpenAI are backend-only integrations. The browser cannot supply provider credentials, call providers directly, or override provider validation. Before a structured AI prompt leaves the backend, the payload is minimized and redacted for common secrets and direct identifiers. External results are still treated as untrusted data and converted to bounded internal values before persistence.

For AI-assisted asset matching, the backend returns a preview response first and only writes vulnerabilities after an administrator submits the approved CPE. The preview output is advisory, while the apply step is the explicit write boundary.

## Failure Containment

The application uses layered error boundaries. Repository and external failures are translated by services, then mapped by controllers to safe responses. Detailed causes remain available to protected logs and error chains, not browser responses.

See [api-error-handling.md](api-error-handling.md) for the error contract.

## Walkthrough: Alice And Bob

- Alice is authenticated.
- Bob owns a different asset.
- Alice requests an asset by identifier.
- The API receives the request after authentication middleware runs.
- The controller binds the request, the service applies the ownership rule, and the repository filters the database query.
- An identifier is not permission. Alice must not read Bob's record by guessing its ID.
- The server derives Alice's identity from authentication context and requires both the asset ID and Alice's owner ID in the lookup.

## Invariants

- Authorization is enforced by the backend.
- Ownership is derived from authenticated server state.
- Sensitive writes are validated and transactional where required.
- Soft-deleted records are excluded from active workflows.
- Secrets, tokens, SQL, and provider payloads are not exposed to clients.
- Angular guards improve navigation but do not provide security.

## Key Terms

- Trust boundary: The point where data changes from untrusted input into an accepted system value.
- Principal: The authenticated identity attached to a request.
- Ownership scope: The user or organization boundary applied to a database query.
- Backend-only integration: An external provider connection unavailable to browser code.
