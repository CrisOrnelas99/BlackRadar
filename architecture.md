# SecureOps Architecture

## Purpose

This document describes the architecture of SecureOps. It is the technical reference for developers and maintainers.

It covers:

- system boundaries
- component responsibilities
- data and API design
- current implementation assumptions
- planned extensions

`Roadmap.md` remains the implementation tracker. - Creator only
`SECURITY.md` is the mandatory security policy for implementation work in this repository.
`CLEANCODE.md` defines code structure, package responsibilities, and implementation conventions.

## System Overview

SecureOps is a cybersecurity asset risk platform.

It supports:

- asset inventory for organizations, applications, home networks, and other inventory sources
- vulnerability tracking and assignment
- CVE ingestion from NVD/NIST
- AI-assisted asset extraction from raw text or file content
- asset-scoped chatbot explanations
- workflow support for remediation and alerts

The system is organized into these main components:

- Angular frontend for UI and client-side routing
- Go Gin/GORM backend as the trust boundary and orchestration layer
- PostgreSQL for persistence
- Docker Compose for the current local backend and database stack
- focused Go services for alerting and CVE refresh

Authentication uses short-lived JWT access tokens plus longer-lived refresh tokens that are stored and validated server-side.

## High-Level Architecture

```text
Browser
  |
  v
Angular frontend
  |
  v
Go Gin/GORM backend
  |
  +--> PostgreSQL
  |
  +--> organization/application/home network scoping
  |
  +--> alert-service-go
  |
  +--> cve-sync-service-go
  |
  +--> NVD / NIST APIs
  |
  `--> AI provider API
```

### Request flow

1. User interaction occurs in the browser.
2. Angular sends authenticated HTTP requests to the Go backend.
3. The backend validates requests, enforces authorization, and executes business logic.
4. The backend persists and queries PostgreSQL.
5. The backend optionally calls internal services or external APIs for alerts, sync, NVD, or AI.
6. The backend returns safe, structured responses to Angular.

### Security boundary

The backend is the main system boundary.

- Angular must never call NVD directly.
- Angular must never call AI providers directly.
- Angular must never call internal Go services directly.
- Backend authorization and validation are the source of truth.

## Repository Structure

The repository is structured around the application and supporting services.

```text
AssetManagementRisk/
|-- backend-Go/
|-- frontend-angular/
|-- docker-compose.yml
|-- .env
|-- README.md
|-- Roadmap.md
|-- AGENTS.md
|-- SECURITY.md
`-- ARCHITECTURE.md
```

### Backend layout

```text
backend-Go/
|-- api/
|   |-- config/
|   |-- controller/
|   |-- dto/
|   |-- external/
|   |-- middleware/
|   |-- model/
|   |-- repository/
|   |-- security/
|   |-- service/
|   `-- utils/
|-- Dockerfile
|-- go.mod
|-- go.sum
`-- main.go
```

### Frontend layout

A feature-based Angular structure is recommended:

```text
frontend-angular/
|-- src/app/
|   |-- core/
|   |   |-- services/
|   |   |-- guards/
|   |   `-- interceptors/
|   |-- features/
|   |   |-- auth/
|   |   |-- dashboard/
|   |   |-- assets/
|   |   |-- vulnerabilities/
|   |   |-- alerts/
|   |   `-- chat/
|   |-- shared/
|   |   |-- models/
|   |   `-- components/
|   `-- app.routes.ts
```

## Component Responsibilities

### Frontend

The Angular application owns:

- authentication screens
- main navigation and routing
- asset and vulnerability management UI
- dashboard and alert views
- NVD import initiation flows
- chatbot UI
- work order and remediation screens
- backend API integration via services
- access-token attachment for protected requests

### Backend

The Go backend owns:

- authentication, access-token generation, refresh-token rotation, and session revocation
- authorization and permission middleware
- organization and tenancy enforcement
- asset and vulnerability CRUD
- asset-vulnerability assignment
- workflow orchestration
- NVD integration and AI-assisted matching
- raw-text/file ingestion via AI agent
- chatbot orchestration
- alert and sync service coordination
- safe error handling and input validation
- audit logging

### Database

PostgreSQL stores:

- users and organizations
- assets
- vulnerabilities
- asset-vulnerability assignments
- remediation workflows
- alerts and sync history
- chat and comment context

## Data Design

### Main entities

- organizations
- users
- assets
- vulnerabilities
- asset_vulnerabilities
- work_orders
- checklist_items
- vulnerability_exceptions
- remediation_entries
- comments
- alerts
- chat context
- sync history

### Relationships

- organizations own users, assets, vulnerabilities, and workflows
- assets can have many vulnerabilities
- vulnerabilities can be assigned to many assets
- work orders link assets, vulnerabilities, and remediation activity
- comments and entries provide team context

### Asset model

Key fields:

- `id`
- `organizationId`
- `userId`
- `name`
- `type`
- `vendor`
- `product`
- `version`
- `ipAddress`
- `operatingSystem`
- `owner`
- `criticality`
- `riskScore`
- `riskLevel`
- `cpeName`
- `cpeMatchConfidence`
- `cpeMatchMethod`
- `lastNvdSyncAt`
- `createdAt`
- `updatedAt`

### Vulnerability model

Key fields:

- `id`
- `organizationId`
- `cveId`
- `title`
- `severity`
- `description`
- `status`
- `source`
- `sourceReference`
- `cvssScore`
- `cvssVector`
- `publishedAt`
- `lastModifiedAt`
- `createdAt`
- `updatedAt`

## API Design

### Existing endpoints

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/assets`
- `GET /api/assets/{id}`
- `POST /api/assets`
- `PUT /api/assets/{id}`
- `DELETE /api/assets/{id}`
- `POST /api/assets/{assetId}/vulnerabilities/{vulnerabilityId}`
- `DELETE /api/assets/{assetId}/vulnerabilities/{vulnerabilityId}`
- `GET /api/vulnerabilities`
- `GET /api/vulnerabilities/{id}`
- `POST /api/vulnerabilities`
- `PUT /api/vulnerabilities/{id}`
- `DELETE /api/vulnerabilities/{id}`

### Planned endpoints

- `POST /api/assets/{id}/import-nvd-vulnerabilities`
- `POST /api/assets/{id}/chat`
- `GET /api/assets/{id}/alerts`
- `POST /api/organizations/{orgId}/work-orders`
- `GET /api/organizations/{orgId}/work-orders`
- `GET /api/organizations/{orgId}/work-orders/{id}`
- `PATCH /api/organizations/{orgId}/work-orders/{id}`
- `DELETE /api/organizations/{orgId}/work-orders/{id}`
- workflow checklist, exception, entry, and comment endpoints
- `POST /api/sync/nvd`
- `GET /api/alerts`
- `PATCH /api/alerts/{id}/acknowledge`

### Response rules

Response payload design follows the repository's DTO separation and controller-to-service mapping conventions.
For detailed coding guidance on request and response design, see `CLEANCODE.md`.
For error handling and safe response behavior, see `SECURITY.md`.

## Security Architecture

`SECURITY.md` is the canonical security checklist and coding-agent policy for this repository. This document describes architecture assumptions and trust boundaries only; it does not duplicate mandatory security controls.

The backend is the main trust boundary. Authentication, authorization, input validation, secret management, and logging controls are defined in `SECURITY.md`.

Architecture notes:

- The frontend must never bypass the backend for protected resources or external integrations.
- Backend responsibility includes tenant isolation, role-based access, and data ownership enforcement.
- External APIs such as NVD and AI providers are accessed only through the backend.
- Secrets and provider keys are server-side only.
- Defensive request filtering and safe response handling are architecture considerations; their required controls are documented in `SECURITY.md`.

Future workflow data files can join the model and DTO layers as needed:

```text
api/model/
|-- work_order.go
|-- work_order_checklist_item.go
|-- vulnerability_exception.go
|-- remediation_entry.go
`-- comment.go
```

Future workflow-focused packages can live alongside the existing layers, such as:

```text
api/
|-- organizations/
|-- workflow/
|-- work_orders/
|-- checklist_items/
|-- vulnerability_exceptions/
|-- remediation_notes/
|-- comments/
`-- chatbot_context/
```

> Design comment: `nvd`, `ai`, and `chat` belong in the main Go backend because they depend on authorization, database rules, DTO mapping, and application-level trust decisions. They should not be pushed into separate services just because they talk to external services.

### Backend layer rules

The main Go backend should keep this dependency direction:

```text
controller -> service -> repository -> database
```

Controllers handle HTTP requests, services orchestrate use cases, and repositories manage persistence.
For implementation conventions and layer responsibilities, see `CLEANCODE.md`.

### DTO and model placement

The current code separates database/domain structs from request/response DTO structs.
Database/domain structs live in `api/model`, and request/response DTOs live in `api/dto`.
See `CLEANCODE.md` for implementation conventions.

### Error handling layout

Error types and mapping are part of the implementation conventions.
See `CLEANCODE.md` for the repository’s error handling style and `SECURITY.md` for response safety requirements.

### Core backend flows

#### Register flow

1. Client sends registration data to `POST /api/auth/register`.
2. Backend validates required fields and uniqueness rules.
3. Password is hashed with BCrypt.
4. User is saved in PostgreSQL with the default `user` role.
5. Backend returns a safe success response without sensitive fields.

> Security comment: registration must not let a client choose `admin`. Admin users should be created through a controlled local, seeded, or admin-only process.

#### Login flow

1. Client sends credentials to `POST /api/auth/login`.
2. Backend resolves the identifier by shape: email-like values are treated as email, everything else is treated as username.
3. BCrypt verifies the password.
4. Backend generates a short-lived access token and a refresh token that share a session ID.
5. Backend stores the refresh session server-side.
6. Backend returns a login response DTO with both tokens and the user summary.

#### Protected request flow

1. Angular sends a request with `Authorization: Bearer <access token>`.
2. JWT filter extracts the token.
3. Backend validates the signature, issuer, audience, scope, token use, and expiry.
4. Backend looks up the access-token session ID in server-side refresh-session storage.
5. Gin authentication middleware establishes the authenticated request context only if the session is still active.
6. The authenticated database user ID is attached to `GinContext`.
7. Controller logic runs only if access is allowed.

#### Refresh flow

1. Client sends the refresh token to `POST /api/auth/refresh`.
2. Backend validates the refresh token and its session ID.
3. Backend confirms the session is still active in PostgreSQL.
4. Backend revokes the old session and rotates to a new session ID.
5. Backend returns a new access token and refresh token pair.

#### Logout flow

1. Client sends the refresh token to `POST /api/auth/logout`.
2. Backend validates the refresh token and its session ID.
3. Backend revokes the stored refresh session.
4. The refresh token can no longer be used.
5. The paired access token also stops working because protected requests check the session table.

#### Asset creation flow

1. User creates an asset.
2. Backend validates asset fields.
3. Backend attaches the authenticated user's ID to the asset.
4. Backend stores the asset in PostgreSQL.
5. Asset is available for later NVD import and risk work.

> Implementation note: asset creation and NVD import should be separate at first. That keeps the create flow fast and avoids coupling user data entry to external API latency.

#### NVD import flow

This should follow Option B:

1. User creates the asset first.
2. User clicks `Find Vulnerabilities from NVD`.
3. The Go backend loads the asset.
4. The Go backend builds a product fingerprint from `vendor`, `product`, `version`, and related metadata.
5. The Go backend searches NVD CPE data.
6. AI may help rank candidate matches when there is ambiguity.
7. The Go backend selects or confirms the best CPE.
8. The Go backend queries NVD CVEs using that selected CPE.
9. The Go backend maps the returned CVE data to local vulnerability records.
10. The Go backend assigns those vulnerabilities to the asset.
11. Risk data can be updated later when risk scoring is reintroduced.

> Security comment: the NVD API is the vulnerability source of truth. AI may help rank or explain relevance, but AI should not invent vulnerabilities or silently override official data.

#### Asset chat flow

1. User opens an asset detail page.
2. User asks a chat question.
3. Angular sends the question to `POST /api/assets/{id}/chat`.
4. The Go backend verifies the user is allowed to view that asset.
5. The Go backend loads only the relevant asset context.
6. The Go backend builds a constrained prompt from local data plus stored NVD metadata.
7. The Go backend calls the AI provider.
8. The Go backend returns a read-only natural-language response.

> Security comment: the chatbot should explain and summarize. It should not directly mutate assets, vulnerabilities, assignments, or risk scores.

## NVD / NIST Integration Design

### Why this belongs in the Go backend

NVD integration is mostly:

- HTTP integration
- DTO mapping
- validation
- persistence
- deduplication
- asset-to-product matching
- authorization-aware business logic

Those are already main-backend responsibilities.

### Asset fingerprinting

For reliable matching, an asset should include:

- `name`
- `type`
- `vendor`
- `product`
- `version`
- `operatingSystem`
- optional deployment notes or environment tags

> Concept comment: `Firewall-01` is a useful asset label, but it is not a vulnerability lookup key. NVD matching works much better when the app knows what product and version the asset actually runs.

### Recommended stored fields

On `Asset`, plan for fields like:

- `vendor`
- `product`
- `version`
- `cpeName`
- `cpeMatchConfidence`
- `cpeMatchMethod`
- `lastNvdSyncAt`

### Local vulnerability storage

NVD results should be stored locally in PostgreSQL.

Benefits:

- faster UI reads
- stable dashboard data
- historical comparison
- less rate-limit pressure
- easier relevance review
- easier risk recalculation

> Security comment: do not live-query NVD every time a page loads. That would be slow, noisy, harder to secure, and more likely to create inconsistent user-facing results.

## AI-Assisted Matching Design

### Role of AI

AI should be a supporting layer, not the truth layer.

AI can help:

- normalize vendor and product names
- rank likely CPE matches
- explain why a given CPE seems relevant
- rank CVEs by likely relevance to the asset
- explain risk in plain English

AI should not:

- invent CVEs
- replace NVD as source of truth
- bypass authorization
- silently auto-import weak matches with no confidence threshold

### AI Agent Architecture for Asset Ingestion

The AI ingestion agent should be implemented as a backend-only orchestration layer that accepts sanitized raw text or file content and converts it into structured asset records.

Key principles:

- The frontend sends only user-provided text or file payload metadata to the backend. AI provider keys, prompts, and routing remain server-side only.
- The backend validates and sanitizes incoming content before using AI, including file type restrictions, size limits, and secret-stripping from pasted data.
- Supported inputs should include package manifests, network asset lists, inventory documents, local scan exports, and other free-form asset descriptions.
- The agent should extract asset metadata such as name, type, vendor, product, version, operating system, IP address, ownership, environment, and confidence metadata.
- The backend should map extracted results into the correct scope: organization, application portfolio, home network, or other inventory context.
- Audit logs should record ingestion input sources, AI-extracted outputs, and the user who initiated the ingestion.
- AI-generated suggestions should be treated as guidance. The backend should apply deterministic rules and review thresholds before committing extracted assets into the system.

### Recommended pattern

1. deterministically query candidate CPEs from NVD
2. give the AI only the asset details and candidate options
3. ask the AI to rank the candidates and explain confidence
4. if confidence is high, continue
5. if confidence is low, require user confirmation

> Security comment: this is the safe way to use AI in a security tool. The model helps interpret ambiguity, but deterministic systems still control data integrity.

## Chatbot Design

### Purpose

The chatbot should answer asset-specific questions such as:

- what vulnerabilities affect this asset
- why this asset is high or critical risk
- which CVEs should be prioritized
- what changed after a sync or recalculation
- why a vulnerability was imported
- what the risk score means in plain English
- what work order is active for this asset
- which checklist items are done or still open
- what remediation notes or comments the team has already written

### Scope

The first version should be organization-scoped and asset-scoped, not global.

Recommended endpoint:

- `POST /api/assets/{id}/chat`
- later: `POST /api/organizations/{orgId}/chat/context`

### Grounding strategy

The chatbot should answer using:

- organization membership and tenant scope
- asset data from PostgreSQL
- assigned vulnerability data
- CVE details and source metadata
- work order status and priority
- checklist state
- remediation entries
- comments and team notes
- stored NVD metadata
- risk score and risk level
- alert summaries if useful
- sync history if useful

It should not depend on live internet lookups for every answer.

> Security comment: grounded answers are safer than open-ended chat because the model is less likely to hallucinate when it is anchored to local records.

### Chat security rules

- require authentication
- require asset-level authorization
- rate limit chat requests
- limit prompt size
- sanitize user-provided text before prompt construction where needed
- never include secrets, tokens, or hidden internal config in prompts
- treat model output as untrusted text
- render chat output safely in Angular

## Go Services Architecture

Go should remain focused on narrow services that are easy to reason about and easy to secure.

### 1. `alert-service-go`

Purpose:

- detect and process important security events

Examples:

- new critical CVE imported for an asset
- risk score crosses a threshold
- repeated NVD sync failures
- asset becomes newly critical

Possible outputs:

- create alert records
- return event severity
- later send notifications or webhook events

> Design comment: this service should stay focused on alert evaluation and alert generation. It should not become a general-purpose workflow engine.

### 2. `cve-sync-service-go`

Purpose:

- refresh previously imported CVE data on a schedule or on demand

Examples:

- sync modified CVE metadata
- refresh CVSS values
- detect changed NVD records
- update asset vulnerability freshness state

> Implementation note: this service does not replace the main Go backend as the owner of NVD import business rules. It supports refresh and synchronization work. The main Go backend still owns the core application workflow and persistence decisions.

### Why not move NVD or chatbot into Go

Those responsibilities depend heavily on:

- authorization
- DTO control
- asset ownership rules
- database writes
- trust-boundary decisions
- prompt safety

That makes the main Go backend the better home for them.

### Service-to-service authentication

Future internal Go services should not accept privileged work just because a request reaches their port. When the main backend calls `alert-service-go`, `cve-sync-service-go`, or another focused service, the call should include a server-side service credential.

Recommended first version:

- keep the service credential in environment-backed backend and service configuration
- send it only from the Go backend to the internal service
- reject missing or invalid service credentials with a generic `401` or `403`
- expose `/health` for basic liveness checks without secrets
- expose `/ready` for dependency readiness checks if the service has dependencies

This is the practical handshake for this project: the backend proves it is an authorized internal caller before the service performs privileged work. More complex options such as mutual TLS can be considered later during hardening.

## Docker and Environment Design

### Compose responsibilities

`docker-compose.yml` should eventually orchestrate:

- PostgreSQL
- Go Gin/GORM backend
- Angular frontend
- `alert-service-go`
- `cve-sync-service-go`

### Networking rules

- Angular should call the Go backend
- the Go backend should call PostgreSQL and Go services by service name inside Docker
- internal Go service calls should use service-to-service authentication for privileged actions
- the Go backend should call external APIs over outbound network access
- Angular should never call NVD directly
- Angular should never call AI providers directly
- Angular should never call Go services directly

Local development has two supported run modes:

- Docker Compose mode: the backend container reaches PostgreSQL through the Docker service name `postgres` on container port `5432`.
- Local backend mode: `go run .` runs from `backend-Go/` and reaches the PostgreSQL container through the published host port, such as `127.0.0.1:15432` when Windows already has another PostgreSQL process on `5432`.

In local backend mode, the Go process reads environment variables from the shell session.
It does not automatically load the root `.env` file.
Set `DATABASE_URL` and `JWT_SECRET` before running `go run .`.
Set `BOOTSTRAP_DEV_DATA=true` only when you want local development seed data.
That bootstrap creates a test admin user, one test device asset, one example CVE vulnerability, and the asset-to-vulnerability assignment after migrations run.
The bootstrap is disabled by default and must not run in production.

In Docker Compose mode, the backend container sets `BOOTSTRAP_DEV_DATA=true` so the seeded test account exists after a fresh compose start.

### Environment variables

Typical values should include:

- database host
- database port
- database name
- database username
- database password
- JWT secret
- JWT access-token expiration
- JWT refresh-token expiration
- NVD API key
- optional development bootstrap flag
- AI provider API key
- alert service base URL
- cve sync service base URL
- frontend API base URL

`Roadmap.md` should remain the canonical checklist for what is done and what is next. - Creator only
