# BlackRadar Security Platform Architecture

## Purpose

This document describes the current technical architecture of BlackRadar Security Platform.
Use it with `README.md`, `CLEANCODE.md`, and `SECURITY.md`.

## System Overview

BlackRadar Security Platform is a cybersecurity asset-risk platform built around:

- Angular frontend
- Go Gin/GORM backend
- PostgreSQL persistence
- NVD / NIST vulnerability data
- backend OpenAI-assisted asset creation, product matching, and vulnerability relevance support
- focused Go services for limited background tasks
- HTTPS/TLS termination at the deployment boundary with server-side certificate handling
- planned backend-issued certificates for privileged internal service authentication
- GitHub Actions CI/CD for automated validation, build artifacts, and protected releases
- future AWS deployment can host the backend, database, certificates, logging, scheduled jobs, and dedicated single-tenant instances through managed services
- organization-scoped tenancy enforced by the backend
- request-scoped GORM transactions for atomic backend request handling
- future multi-organization membership can be layered on top of the tenant boundary with server-side active-organization switching

The backend is the trust boundary. Angular never talks directly to NVD, OpenAI, or internal services.

## Current Runtime Shape

- Frontend: Angular application
- API: Go backend in `backend-Go/`
- Database: PostgreSQL
- Local orchestration: Docker Compose
- Secure deployments should terminate TLS in a reverse proxy or in the Go backend, but certificates stay server-side
- Request-scoped GORM middleware opens one database transaction per HTTP request and stores it on `GinContext`
- Planned internal service auth: backend-issued certificates for privileged `/internal` service calls
- AWS is a later deployment layer, not a replacement for the backend trust boundary

## Backend Responsibilities

The Go backend owns:

- authentication
- access-token generation
- refresh-token rotation and session revocation
- authorization and permission checks
- organization membership and tenant scoping
- asset CRUD
- vulnerability CRUD
- asset-to-vulnerability assignment
- NVD lookup and local vulnerability persistence
- NVD CPE candidate lookup for saved assets
- OpenAI-backed asset extraction from raw text
- OpenAI-backed CPE candidate ranking and bounded CVE relevance ranking
- persistence of linked asset-assessment data for risk score, product fingerprint, selected CPE, confidence, review status, review notes, candidate count, and match timestamp
- admin-only AI provider diagnostics
- endpoint rate limiting for auth, NVD lookup, and AI-assisted paths
- structured request logging and security logging
- safe error handling and input validation
- request transaction lifecycle management through middleware
- planned internal service certificate authority duties for onboarding, signing, and verifying focused Go service identities
- cloud deployment compatibility for managed services such as ECR, ECS/Fargate, RDS, ALB/ACM, CloudWatch, Secrets Manager, and EventBridge
- CI/CD compatibility for GitHub Actions workflows, required checks, and artifact promotion

## Auth Model

The current auth model uses short-lived JWT access tokens and server-side refresh-token sessions.

Important notes:

- access tokens are short-lived
- refresh tokens are stored and validated server-side through the refresh-session table
- login and refresh responses include `tokenExpiresAt` and `refreshTokenExpiresAt`
- logout revokes the stored session
- protected requests check both the access token and the active session state
- login resolves `userOrEmail` by shape: email-like values use email lookup, everything else uses username lookup
- registration requires an organization name, and the backend resolves or creates the organization server-side
- auth and NVD lookup requests are rate limited in the backend
- outbound TLS verification remains enabled for external API calls such as NVD

### Flow Summary

1. Client posts credentials to `POST /api/auth/login`.
2. Backend verifies the password.
3. Backend issues an access token and refresh token pair.
4. Backend stores the refresh session in PostgreSQL.
5. Login and refresh responses return the user first, then the access token, access expiry, refresh token, and refresh expiry.
6. Protected requests use `Authorization: Bearer <access token>`.
7. Refresh requests use `POST /api/auth/refresh` with the refresh token in the body.
8. Logout uses `POST /api/auth/logout` with the refresh token in the body.

> Note: access-token and refresh-token character length is an implementation detail, not a security property. In this codebase both are JWTs, so length should not be used as a design rule.

## Data Model

Core current entities:

- organizations
- users
- assets
- vulnerabilities
- asset_vulnerabilities
- refresh_sessions

Organizations are the tenant boundary. Users belong to one organization, and assets and vulnerabilities are queried by organization membership.

Current delete behavior uses GORM soft deletes for core records that need auditability and recovery semantics. Models include `gorm.DeletedAt`, so normal GORM queries automatically exclude rows where `deleted_at` is set.

Assets keep core inventory data in `assets`, while AI/NVD match state and mutable scoring live in a linked `asset_assessments` record. `risk_level` stays null until vulnerabilities are attached and the backend derives a value from their severities:

- risk_score
- product_fingerprint
- selected_cpe
- cpe_confidence
- cpe_review_status
- cpe_review_notes
- cpe_candidate_count
- cpe_matched_at

Planned data expansion includes:

- organization memberships and active organization state
- work orders and checklist items
- vulnerability exceptions and remediation entries
- comments and team notes
- alerts and alert acknowledgements
- chat sessions and retrieved context records
- CVE sync history and import audit records
- soft-delete metadata such as `deleted_at` on security-sensitive and audit-relevant records

## Soft Delete Model

The backend uses GORM soft deletes for security-sensitive and audit-relevant records by adding `gorm.DeletedAt` or equivalent `deleted_at` metadata to models and schema.

Behavior:

- Normal application deletes mark `deleted_at` instead of physically removing rows.
- Normal GORM queries exclude soft-deleted rows.
- `Unscoped()` is reserved for explicit cleanup, retention, or administrative recovery paths.
- Unique indexes that must allow reuse after deletion are scoped to active rows, for example `WHERE deleted_at IS NULL`.
- The asset-vulnerability bridge includes `deleted_at`; repository joins explicitly filter active bridge rows because GORM does not automatically apply soft-delete predicates to every joined table.
- Authentication and authorization continue to revalidate live database state so deleted or disabled users, revoked sessions, and removed permissions cannot keep access through stale JWT claims.
- Soft-deleted records should remain available for audit, incident response, and recovery according to retention policy.

## Request-Scoped Database Transactions

The current Go backend uses request-scoped GORM transactions for normal HTTP request handling.

Flow:

1. `RequestContext` creates the request-scoped `GinContext`.
2. `GormMiddleware` begins a GORM transaction for the request.
3. The transaction is stored on `GinContext` through `SetDatabase`.
4. Controllers, services, and repositories receive the same `GinContext`.
5. Repositories call their context-aware database helper and use the request transaction instead of the base database handle.
6. At the end of the request, the middleware commits only when the response status is `200` through `203` and no Gin context errors were recorded.
7. The middleware rolls back when the request returns another status, records context errors, fails to begin cleanly, or panics.

Nested `db.Transaction(...)` calls inside repositories or services run under the request transaction. With GORM and PostgreSQL, those nested transactions become savepoints, which lets focused operations roll back locally without abandoning the entire outer transaction when the code intentionally handles the inner error.

Design rules:

- Middleware owns the request transaction lifecycle.
- Repositories do not call `Begin`, `Commit`, or `Rollback` for the request itself.
- Repositories may still use focused nested GORM transactions for multi-step persistence operations and savepoint behavior.
- External calls such as NVD and OpenAI should happen before expensive database writes when practical so request transactions stay short.
- Handlers and services must return safe errors and status codes consistently because non-success responses cause rollback.

## Layered Error Handling

The backend uses a layered error-handling model across repository, service, and controller packages.

Flow:

```text
Database / external dependency error
        |
        v
Repository sentinel error
        |
        v
Service sentinel error
        |
        v
Controller status mapping
        |
        v
HandleError JSON response
```

Repository packages own persistence-level errors such as not found, duplicate data, invalid reference, and create/read/update/delete failures. Repositories wrap database or constraint errors with repository sentinels using `%w` so the original cause remains available to `errors.Is` and `errors.As`.

Service packages translate repository errors into service-level business errors with `TranslateRepositoryError`. The translation preserves both layers by wrapping the service sentinel around the original repository error, for example `fmt.Errorf("%w: %w", ErrNotFound, repoErr)`. Controllers should check service errors only; they must not depend on GORM, PostgreSQL, repository implementations, or repository sentinel names.

Controllers map service errors to HTTP status codes with `errors.Is`, then call the shared `HandleError` helper. `HandleError` logs the internal error and returns a safe JSON response containing a stable code, user-facing message, and request ID. The API does not return stack traces, raw SQL errors, JWT internals, bcrypt errors, or upstream provider details to clients.

## API Surface

Implemented auth routes:

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`

Implemented asset routes:

- `GET /api/assets`
- `GET /api/assets/{id}`
- `POST /api/assets`
- `PUT /api/assets/{id}`
- `DELETE /api/assets/{id}`

`POST /api/assets` supports normal structured asset creation and backend AI-assisted creation from `rawText` when `aiMode` is enabled.

Implemented vulnerability routes:

- `GET /api/vulnerabilities`
- `GET /api/vulnerabilities/{id}`
- `POST /api/vulnerabilities` accepts `cveId`, `title`, `severity`, `description`, and `status`
- `PUT /api/vulnerabilities/{id}`
- `DELETE /api/vulnerabilities/{id}`

Implemented assignment routes:

- `POST /api/assets/{assetId}/vulnerabilities/{vulnerabilityId}`
- `POST /api/assets/{assetId}/match-cpe/vulnerabilities`
- `DELETE /api/assets/{assetId}/vulnerabilities/{vulnerabilityId}`

Implemented NVD route:

- `GET /api/nvd/cves/{cveId}`

Implemented AI diagnostic routes:

- `GET /api/ai/test`
- `POST /api/ai/message`

## Planned Backend Surfaces

The backend remains the trust boundary for future feature work. Planned surfaces include:

- `GET /api/organizations`
- `POST /api/organizations/switch`
- `POST /api/assets/{id}/chat`
- `POST /api/sync/nvd`
- `GET /api/alerts`
- `PATCH /api/alerts/{id}/acknowledge`
- admin-only handshake-token creation for onboarding internal services
- internal-service handshake for exchanging a one-time token and CSR for a signed service certificate
- certificate-protected `/internal` routes for focused Go service calls
- organization-scoped work order, checklist, exception, remediation, and comment endpoints
- dashboard summary endpoints
- future Angular-facing organization and workflow endpoints remain backend-authenticated and organization-scoped

## Planned Internal Service Authentication

Future focused Go services, such as alert evaluation or CVE synchronization workers, should not authenticate to privileged backend routes with browser JWTs, shared passwords, or static bearer tokens. Internal service identity should use backend-issued certificates.

Planned flow:

1. An administrator with the appropriate configuration permission creates a short-lived, one-time handshake token.
2. The internal service generates its own key pair and CSR.
3. The service calls a backend handshake endpoint with the one-time token and CSR.
4. The backend validates that the token exists, is unexpired, and has not been consumed.
5. The backend signs the CSR with its configured internal CA private key and returns a signed service certificate.
6. Later privileged internal requests include the signed certificate in a dedicated internal-auth header or equivalent internal transport mechanism.
7. Certificate authentication middleware parses the certificate, verifies that it was signed by the backend CA, checks expiration, extracts the service identity such as OU, and adds that identity to request context.
8. Route-level middleware checks whether that service identity is allowed to call the specific internal route.

Design rules:

- This is separate from public HTTPS/TLS certificates used at the deployment boundary.
- The one-time handshake token is only an onboarding secret; it is not a long-term credential.
- Service private keys must be generated and stored by the service, never by Angular or browser code.
- The backend CA private key must come from environment-specific secret management, not source control.
- Certificates should carry a constrained service identity such as `alert-service` or `cve-sync-service`.
- A valid certificate proves service identity, but route-level authorization still decides what that service can do.
- Handshake attempts, certificate issuance, validation failures, and route denials should be logged without raw tokens, private keys, or full certificate bodies.

## NVD / Vulnerability Handling

NVD integration lives in the backend because it needs:

- HTTP access
- request validation
- DTO mapping
- safe persistence
- authorization-aware business logic

NVD results are stored locally instead of live-querying the browser repeatedly.

## AI-Assisted Asset Matching

AI integration is backend-only. The current backend uses OpenAI for bounded assistance, while NVD remains the source of truth for CPE and CVE data.

Implemented backend AI flows:

- create one asset draft from raw text through `POST /api/assets` with `aiMode`
- build a product fingerprint from saved asset data and sanitized text
- query NVD CPE candidates through the backend
- ask OpenAI to rank only the provided NVD CPE candidates
- store selected CPE, confidence, review status, review notes, candidate count, and match time in the linked asset assessment
- fetch NVD CVEs for the selected CPE and attach bounded results to the asset
- use keyword fallback and AI CVE ranking only against NVD-returned CVE candidates

Safety boundaries:

- OpenAI credentials stay server-side.
- Prompts are locked in backend code.
- User text is treated as untrusted data.
- Model output must be JSON and is validated before use.
- AI may rank, extract, and summarize, but it must not invent vulnerabilities or override NVD data.
- Ambiguous or low-confidence results are marked `needs_review`.

## Code Structure

The backend follows:

```text
controller -> service -> repository -> database
```

Package roles:

- `controller`: HTTP binding and responses
- `service`: business rules and orchestration
- `repository`: persistence
- `model`: database/domain structs
- `dto`: request and response shapes
- `middleware`: request auth and guards
- `security`: JWT and token helpers
- `utils`: database and identifier helpers

## Environment

Typical local variables:

- `DATABASE_URL`
- `JWT_SECRET`
- `JWT_EXPIRATION_MS`
- `JWT_REFRESH_EXPIRATION_MS`
- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `POSTGRES_PORT`
- `NVD_API_KEY`
- `OPENAI_API_KEY`
- `OPENAI_MODEL`
- `OPENAI_TIMEOUT_SECONDS`
- `BOOTSTRAP_DEV_DATA`

## Security Notes

See `SECURITY.md` for the full policy.

Key current rules:

- do not trust browser-side authorization
- do not expose secrets to the frontend
- use backend validation and authorization
- keep NVD and AI calls server-side
- store imported vulnerability data locally
- keep future organization switching, workflow actions, and background services backend-authenticated and tenant-scoped
- require certificate-based service identity and route-level service authorization before exposing privileged `/internal` routes
