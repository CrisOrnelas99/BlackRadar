# SecureOps Architecture

## Purpose

This document describes the current technical architecture of SecureOps.
Use it with `README.md`, `CLEANCODE.md`, and `SECURITY.md`.

## System Overview

SecureOps is a cybersecurity asset-risk platform built around:

- Angular frontend
- Go Gin/GORM backend
- PostgreSQL persistence
- NVD / NIST vulnerability data
- backend OpenAI-assisted asset creation, product matching, and vulnerability relevance support
- focused Go services for limited background tasks
- HTTPS/TLS termination at the deployment boundary with server-side certificate handling
- GitHub Actions CI/CD for automated validation, build artifacts, and protected releases
- future AWS deployment can host the backend, database, certificates, logging, scheduled jobs, and dedicated single-tenant instances through managed services
- organization-scoped tenancy enforced by the backend
- future multi-organization membership can be layered on top of the tenant boundary with server-side active-organization switching

The backend is the trust boundary. Angular never talks directly to NVD, OpenAI, or internal services.

## Current Runtime Shape

- Frontend: Angular application
- API: Go backend in `backend-Go/`
- Database: PostgreSQL
- Local orchestration: Docker Compose
- Secure deployments should terminate TLS in a reverse proxy or in the Go backend, but certificates stay server-side
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
- persistence of asset product fingerprint, selected CPE, confidence, review status, review notes, candidate count, and match timestamp
- admin-only AI provider diagnostics
- endpoint rate limiting for auth, NVD lookup, and AI-assisted paths
- structured request logging and security logging
- safe error handling and input validation
- cloud deployment compatibility for managed services such as ECR, ECS/Fargate, RDS, ALB/ACM, CloudWatch, Secrets Manager, and EventBridge
- CI/CD compatibility for GitHub Actions workflows, required checks, and artifact promotion

## Auth Model

The current auth model uses short-lived JWT access tokens and server-side refresh-token sessions.

Important notes:

- access tokens are short-lived
- refresh tokens are stored and validated server-side through the refresh-session table
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
5. Protected requests use `Authorization: Bearer <access token>`.
6. Refresh requests use `POST /api/auth/refresh` with the refresh token in the body.
7. Logout uses `POST /api/auth/logout` with the refresh token in the body.

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

Assets also store product matching metadata used by the AI/NVD flow:

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
- `POST /api/assets/{id}/match-cpe`

`POST /api/assets` supports normal structured asset creation and backend AI-assisted creation from `rawText` when `aiMode` is enabled.

Implemented vulnerability routes:

- `GET /api/vulnerabilities`
- `GET /api/vulnerabilities/{id}`
- `POST /api/vulnerabilities`
- `PUT /api/vulnerabilities/{id}`
- `DELETE /api/vulnerabilities/{id}`

Implemented assignment routes:

- `POST /api/assets/{assetId}/vulnerabilities/{vulnerabilityId}`
- `POST /api/assets/{assetId}/vulnerabilities/cve/{cveId}`
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
- organization-scoped work order, checklist, exception, remediation, and comment endpoints
- dashboard summary endpoints
- future Angular-facing organization and workflow endpoints remain backend-authenticated and organization-scoped

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
- store selected CPE, confidence, review status, review notes, candidate count, and match time on the asset
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
