# SecureOps Lite Architecture

## Purpose

This document describes the architecture of SecureOps Lite. It is the technical reference for developers and maintainers.

It covers:

- system boundaries
- component responsibilities
- data and API design
- current implementation assumptions
- planned extensions

`Roadmap.md` remains the implementation tracker. - Creator only

## System Overview

SecureOps Lite is a cybersecurity asset risk platform.

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
- focused Go services for alerting and CVE refresh

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
secureops-lite/
|-- backend-Go/
|-- frontend-angular/
|-- docker-compose.yml
|-- .env
|-- README.md
|-- Roadmap.md
|-- Agents.md
`-- architecture.md
```

### Backend layout

```text
backend-Go/
|-- main/
|-- api/
|   |-- config/
|   |-- controller/
|   |-- dto/
|   |-- middleware/
|   |-- model/
|   |-- repository/
|   |-- security/
|   |-- service/
|   `-- utils/
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
- JWT attachment for protected requests

### Backend

The Go backend owns:

- authentication and JWT generation
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

- never return password hashes
- use DTOs for request and response payloads
- keep auth errors generic
- map service errors to appropriate HTTP responses
- do not leak stack traces or secrets

## Security Architecture

### Authentication and authorization

- hash passwords with BCrypt
- protect backend routes with JWT middleware
- enforce organization membership for org-scoped data
- separate admin-only routes from normal user routes
- never trust client-submitted role values

### Input validation

- validate DTOs in the service layer
- allowlist severity, status, and criticality values
- validate IDs and ownership before mutation
- validate imported upstream data before trusting it

### NVD and external APIs

- keep NVD keys in environment variables
- never expose NVD keys to the frontend
- cache local results instead of live-querying on every page
- handle upstream failures safely

### AI security

- keep AI provider keys server-side only
- restrict prompts to asset-specific context
- defend against prompt injection
- treat model output as advisory text

### RequestFilter

A lightweight request filter should block obvious suspicious input patterns:

- SQL injection-like strings
- XSS-like strings
- path traversal patterns like `../`

This is an additional defensive layer, not a substitute for validation.

### Secrets and config

- keep `.env` out of source control
- treat `.env` as local development configuration only
- avoid hardcoded secrets in code or Docker images

### Logging

- log blocked requests with care
- log authentication and security events when useful
- never log plaintext passwords
- never log full JWTs or secret values
- avoid exposing internal diagnostic details to API consumers

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

Layer responsibilities:

- `controller`: HTTP-only concerns such as Gin context handling, JSON binding, route parameter parsing, and response calls
- `service`: business validation, ownership checks, repository-error translation, and use-case coordination
- `repository`: GORM/database reads and writes only
- `utils`: database connection helpers and database error helpers. The current backend provisions the schema with GORM AutoMigrate at startup rather than a separate SQL migration folder.
- `middleware`: request filtering and Gin middleware behavior
- `security`: JWT generation, parsing, and authentication filtering
- `config`: environment-backed construction of config and dependencies

Interfaces should be owned by the consuming layer:

- service interfaces are exposed by the `service` package for controller use
- controllers receive service interfaces directly through constructors in `main.go`
- `service/repository_interfaces.go` defines the repository interfaces services need
- repository structs satisfy those interfaces implicitly
- service structs satisfy their package interfaces implicitly

This keeps controllers unaware of repository implementations and keeps repositories unaware of HTTP.

### DTO and model placement

The current code separates database/domain structs from request/response DTO structs:

- database/domain structs live in `api/model`: `asset.go`, `user.go`, `vulnerability.go`
- DTO structs live in `api/dto`: `asset_dto.go`, `auth_dto.go`, `vulnerability_dto.go`

DTO files should not live in `controller`. Controllers use DTOs, but DTOs are not controller behavior.

### Error handling layout

Package-level `errors.go` files should stay simple:

```go
type ServiceError struct {
	Message string
}

func (e ServiceError) Error() string {
	return e.Message
}

var (
	ErrInvalidRequestData = &ServiceError{Message: "invalid request data"}
)
```

Rules:

- `errors.go` files contain only the error struct, its `Error()` method, and sentinel vars
- repository errors describe repository/database outcomes only
- service errors are more general business outcomes such as invalid request, conflict, not found, invalid credentials, and forbidden
- middleware and security errors follow the same simple sentinel style
- helper functions and mapping logic belong in normal implementation files, not in `errors.go`
- config does not need `config_errors.go` until config loading returns `(Config, error)`

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
2. Backend loads the user by username or email.
3. BCrypt verifies the password.
4. Backend generates a JWT if credentials are valid.
5. Backend returns a login response DTO with token metadata.

#### Protected request flow

1. Angular sends a request with `Authorization: Bearer <token>`.
2. JWT filter extracts the token.
3. Backend validates the token.
4. Gin authentication middleware establishes the authenticated request context.
5. The authenticated database user ID is attached to `GinContext`.
6. Controller logic runs only if access is allowed.

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

### Environment variables

Typical values should include:

- database host
- database port
- database name
- database username
- database password
- JWT secret
- JWT expiration
- NVD API key
- AI provider API key
- alert service base URL
- cve sync service base URL
- frontend API base URL

`Roadmap.md` should remain the canonical checklist for what is done and what is next. - Creator only
