# 🔒 Security Boundaries

## Overview

BlackRadar treats the backend as the primary trust boundary. The browser is a client of the system, not an authority over identity, ownership, permissions, risk, or external integrations.

This document is the shared security model for the feature docs. Feature-specific workflows should point back here instead of repeating the same rules in every file.

## Trust Model

Trusted decisions come from server-side state:

- authenticated principal and session state
- backend authorization checks
- database organization-scope predicates
- validated domain data
- bounded, backend-controlled external results

Browser input, imported text, AI output, NVD responses, and route parameters stay untrusted until they are validated at the relevant boundary.

## Request Flow

```text
Browser
  -> Angular UX and API client
  -> Gin controller
  -> service business rules
  -> repository persistence
  -> PostgreSQL
```

The controller binds requests and maps responses. The service enforces ownership, validation, authorization, and workflow rules. The repository performs scoped persistence. Middleware establishes authentication, request context, and database sessions.

## Ownership

Current data visibility is organization-scoped. The authenticated user ID comes from the server-side principal; it is never accepted as authoritative request data. The current deployment has one organization, and every active user belongs to it.

Alice must not be able to access Bob’s asset, vulnerability, or relationship by guessing an identifier. Queries therefore scope the relevant record by both its identifier and Alice’s authenticated user ID.

Department and multi-organization membership, switching, and isolation are future work. They must replace the current single-organization resolver before multiple organizations share a database.

## External Integrations

NVD and OpenAI are backend-only integrations. The browser cannot supply provider credentials, call providers directly, or override provider validation. Before a structured AI prompt leaves the backend, the payload is minimized and redacted for common secrets and direct identifiers. External results are still untrusted data and are converted into bounded internal values before persistence.

Outbound OpenAI and NVD requests pass through a local burst limiter and a durable PostgreSQL-backed provider quota. The durable reservation is atomic and shared across backend instances; if quota enforcement cannot be read or updated, the provider call is rejected.

For AI-assisted asset matching, the backend returns a preview response first and only writes vulnerabilities after an administrator submits the approved CPE. The preview output is advisory, while the apply step is the explicit write boundary.

## Failure Containment

The application uses layered error boundaries. Repository and external failures are translated by services, then mapped by controllers to safe responses. Detailed causes stay in protected logs and error chains, not browser responses.

See [api-error-handling.md](api-error-handling.md) for the error contract.

## Walkthrough: Alice And Bob

1. Alice is authenticated.
2. Bob owns a different asset.
3. Alice requests an asset by identifier.
4. Authentication middleware runs first.
5. The controller binds the request, the service applies the ownership rule, and the repository filters the database query.
6. The identifier is not permission. Alice must not read Bob’s record by guessing its ID.
7. The server derives Alice’s identity from authentication context and requires both the asset ID and Alice’s owner ID in the lookup.

## Invariants

- Authorization is enforced by the backend.
- Organization scope is derived from authenticated server state.
- Sensitive writes are validated and transactional where required.
- Soft-deleted records are excluded from active workflows.
- Secrets, tokens, SQL, and provider payloads are not exposed to clients.
- Angular guards improve navigation but do not provide security.

## Key Terms

- **Trust boundary:** The point where data changes from untrusted input into an accepted system value.
- **Principal:** The authenticated identity attached to a request.
- **Ownership scope:** The user or organization boundary applied to a database query.
- **Backend-only integration:** An external provider connection unavailable to browser code.
