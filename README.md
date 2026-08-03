# BlackRadar Security Platform

BlackRadar Security Platform is a focused cybersecurity asset risk platform. It combines asset inventory, vulnerability intelligence, and AI-assisted workflows to help users understand risk across applications, home networks, and imported asset inventories.

For implementation details and agent research notes, use `.agents/skills/architecture/SKILL.md`, `.agents/skills/clean-code/SKILL.md`, `.agents/skills/security/SKILL.md`, and `.agents/skills/roadmap/SKILL.md` together. `README.md` stays at the product and setup level.

## Table of Contents

- [What This Project Is](#what-this-project-is)
- [Getting Started](#getting-started)
- [Architecture](#architecture)
- [Current Capabilities](#current-capabilities)
- [Repository Layout](#repository-layout)
- [API Summary](#api-summary)
- [Data Model Direction](#data-model-direction)
- [Security Approach](#security-approach)
- [Documentation](#documentation)
- [Planned Extensions](#planned-extensions)

## What This Project Is

BlackRadar Security Platform is designed as a practical, developer-friendly security application rather than a full enterprise SIEM. It demonstrates how a secure backend trust boundary, external vulnerability data, and AI-assisted ingestion can work together in one system.

Key capabilities include:

- asset inventory with product-aware metadata
- vulnerability tracking and asset-to-vulnerability assignment
- user-scoped asset and vulnerability separation
- backend-enforced authorization and security controls
- backend rate limiting on auth and NVD lookup endpoints
- short-lived access tokens with server-side refresh-token sessions
- request-scoped GORM database sessions with service transaction boundaries through `platform/transaction`
- backend OpenAI-assisted asset creation, CPE matching, and NVD vulnerability attachment

The platform supports multiple inventory contexts, including applications, home networks, and imported raw asset lists.

## Getting Started

### Requirements

- Docker Desktop
- Node.js for Angular frontend work
- Go for backend development or local builds

### Starting the current backend stack

The current `docker-compose.yml` includes:

- `postgres`
- `backend`
- `frontend`

Start the full Compose stack with:

```bash
docker compose run --rm frontend npm ci
docker compose up --build
```

The frontend dependencies are installed explicitly into the named Docker volume once; the frontend service does not install packages during every startup.
Compose does not enable development bootstrap data by default. To opt in for a local database, set `BOOTSTRAP_DEV_DATA=true` and `BOOTSTRAP_DEV_PASSWORD` in the root `.env` file.
When that password is supplied, the seeded `system_admin` test account is available after a fresh compose start.

Default endpoints:

- backend: `http://localhost:8080`
- frontend: `http://localhost:4200`
- PostgreSQL: mapped from `${POSTGRES_PORT}` to container `5432`

For backend development, it is often simpler to run PostgreSQL in Docker and the Go backend directly from the local shell. This keeps rebuilds fast while still using the same database container.

From the repository root:

```powershell
$env:POSTGRES_PORT = '15432'
docker compose up -d postgres
docker compose ps
```

Use `15432` when another PostgreSQL process is already using local port `5432`. The `docker compose ps` output should show `15432->5432/tcp`.

Then run the backend from `BlackRadar/`:

```powershell
cd BlackRadar
$env:DATABASE_URL = 'postgres://secureops_user:s5e4c3u2r1e@127.0.0.1:15432/secureops'
$env:JWT_SECRET = 't1h2i3s4I5s6A7R8a9n0d1o2m3S4e5c6r7e8t'
$env:BOOTSTRAP_DEV_DATA = 'true'
$env:BOOTSTRAP_DEV_PASSWORD = 'choose-a-local-dev-password'
go run .
```

When using local `go run .`, Go reads environment variables from the PowerShell session. It does not automatically load the root `.env` file. Docker Compose reads `.env` for containers.

`BOOTSTRAP_DEV_DATA=true` is optional. When enabled in local development or tests, startup refreshes a fixed local test setup:

- admin username: `system_admin`
- email: `system_admin@example.invalid`
- password: value from `BOOTSTRAP_DEV_PASSWORD`
- one test device asset
- one assigned example vulnerability: `CVE-2021-44228`

Registration accepts full name, username, email, and password fields. Organization membership is not part of the current implementation.

The bootstrap flag is rejected outside `local`, `development`, and `test` environments. Bootstrap also requires `BOOTSTRAP_DEV_PASSWORD` and does not keep a default password in source control.

If port `8080` is already in use, stop the old local backend process before restarting:

```powershell
netstat -ano | findstr ":8080"
Stop-Process -Id <PID> -Force
```

### Frontend status

The Angular UI lives in `BlackRadar/ui/` and is wired into Docker Compose as the `frontend` service. It should be treated as active local-development UI, not as a production deployment example.
The backend container runs as the unprivileged `blackradar` user with a read-only root filesystem, dropped Linux capabilities, and `no-new-privileges`. Production deployments still need separately managed image digest pinning, TLS, secrets, networking, and runtime policy.

### Environment configuration

This project uses a local `.env` file for development configuration.
Typical values include:

- PostgreSQL database host, port, name, user, password
- JWT secret of at least 32 bytes and token expiration settings
- allowed frontend origins for backend CORS, such as `http://localhost:4200,http://localhost:4000`
- trusted reverse-proxy IPs or CIDR ranges for forwarded client IPs, such as `10.0.0.10,10.0.1.0/24` (`TRUSTED_PROXY_CIDRS`); leave empty when the backend is directly exposed
- frontend SSR API origin for CSP, such as `http://localhost:8080`
- NVD API key
- OpenAI API key
- internal service URLs

Important:

- do not commit secrets
- set `JWT_SECRET`; the backend refuses to start with a missing or weak JWT secret
- do not expose API keys to the frontend
- keep `.env` local to development

## Architecture

BlackRadar Security Platform is intentionally designed with clear component separation. The backend is the primary security boundary and owner of authorization, persistence, external integration, and AI orchestration.

- Angular frontend: UI, authentication, asset and vulnerability workflows, chat UX.
- Go Gin/GORM backend: API, authentication, business logic, data orchestration, NVD/AI integration.
- PostgreSQL: persistent storage for users, assets, vulnerabilities, and workflow state.
- Focused services: asset, AI diagnostics, vulnerability, asset-vulnerability assignment, asset-risk, and AI matching services.
- Backend request logging and rate limiting are applied to sensitive endpoints.

### High-level architecture

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
  +--> NVD / NIST APIs
  `--> OpenAI API
```

### Design principles

- Backend is the main security and trust boundary.
- Frontend never calls NVD, AI providers, or internal services directly.
- Backend enforces validation, authorization, and DTO mapping.
- Backend write workflows request transactions through `platform/transaction`; `platform/db` owns the GORM transaction implementation so partial database updates roll back when the operation fails.
- Controller → service → repository captures request flow.
- Local persistence of imported CVE data is preferred over live UI lookups.

## Current Capabilities

The repository currently contains these working foundations:

- Go Gin/GORM backend foundation
- JWT-based authentication with access and refresh tokens
- permission middleware support
- asset CRUD API and models
- vulnerability CRUD API and models
- asset-to-vulnerability assignment endpoints
- CVE lookup through the backend NVD integration
- backend asset-risk calculation when affected relationships or vulnerabilities change
- NVD CPE candidate search support
- backend OpenAI provider configuration and text-generation boundary
- AI-assisted asset creation from raw text through the backend
- AI-assisted asset product fingerprinting and CPE ranking
- persisted asset assessment metadata, including risk score, product fingerprint, selected CPE, confidence, review status, review notes, candidate count, and matched timestamp
- CPE-based NVD CVE lookup and bounded vulnerability attachment to assets
- admin-only AI diagnostic endpoints
- user-owned assets and vulnerabilities
- PostgreSQL UUID primary keys through embedded model metadata
- request-scoped GORM database sessions with service-owned transaction boundaries implemented through the platform transaction runner
- GORM soft-delete support for audit-relevant records and active-row uniqueness
- `updated_by_id` audit metadata on mutable model records
- repository-level database revalidation for privileged mutations
- ownership predicates on user-owned writes and database-required `user_id` values
- server-generated UUIDs for persisted records; client request DTOs cannot choose record IDs
- layered repository/service/controller error handling with safe JSON responses
- controller → service → repository layering
- GORM AutoMigrate provisioning
- Docker Compose support for PostgreSQL, backend, and frontend
- Angular UI project scaffold under `BlackRadar/ui/`

## Repository Layout

```text
AssetManagementRisk/
|-- .agents/
|   `-- skills/
|       |-- architecture/
|       |   `-- SKILL.md
|       |-- clean-code/
|       |   `-- SKILL.md
|       |-- roadmap/
|       |   `-- SKILL.md
|       `-- security/
|           `-- SKILL.md
|-- .env
|-- .gitignore
|-- AGENTS.md
|-- BlackRadar/
|   |-- Dockerfile
|   |-- api/
|   |   |-- common/
|   |   |-- controller/
|   |   |-- external/
|   |   |-- middleware/
|   |   |-- model/
|   |   |-- platform/
|   |   |-- repository/
|   |   `-- service/
|   |-- docs/
|   |   |-- ai-asset-ingestion.md
|   |   |-- ai-cpe-and-cve-matching.md
|   |   |-- api-error-handling.md
|   |   |-- asset-risk.md
|   |   |-- asset-vulnerability-assignment.md
|   |   |-- assets.md
|   |   |-- database-and-soft-deletes.md
|   |   |-- frontend-angular.md
|   |   |-- infrastructure.md
|   |   |-- nvd-integration.md
|   |   |-- security-boundaries.md
|   |   |-- users-auth-sessions.md
|   |   `-- vulnerabilities.md
|   |-- go.mod
|   |-- go.sum
|   |-- main.go
|   |-- tests/
|   |   |-- AI/
|   |   |-- Admin Setup/
|   |   |-- Assets/
|   |   |-- Non-Admin Setup/
|   |   |-- NVD/
|   |   |-- Vulnerabilities/
|   |   `-- opencollection.yml
|   `-- ui/
|       |-- angular.json
|       |-- package-lock.json
|       |-- package.json
|       |-- postcss.config.mjs
|       |-- public/
|       |   |-- BlackRadar Logo.png
|       |   `-- favicon.ico
|       `-- src/
|           |-- app/
|           |   |-- components/
|           |   |-- config/
|           |   |-- pages/
|           |   `-- services/
|           |-- environments/
|           |-- index.html
|           |-- main.server.ts
|           |-- main.ts
|           |-- server.ts
|           |-- styles.css
|           `-- theme.css
`-- docker-compose.yml
```

Inside `BlackRadar/api/`:

```text
api/
|-- common/
|   |-- id/
|   |-- jwt/
|   `-- token/
|-- controller/
|   |-- ai/
|   |-- asset/
|   |-- health/
|   |-- nvd/
|   |-- shared/
|   |-- user/
|   `-- vulnerability/
|-- external/
|   |-- nvd_cpe/
|   |-- nvd_cve/
|   |-- openai/
|   |-- provider_quota/
|   `-- rate_limiter/
|-- middleware/
|   |-- context/
|   |-- cors/
|   |-- filter/
|   |-- gorm/
|   |-- jwt/
|   |-- permissions/
|   |-- rate_limit/
|   `-- security_headers/
|-- model/
|-- platform/
|   |-- bootstrap/
|   |-- config/
|   |-- db/
|   |-- requestcontext/
|   |-- runtime/
|   `-- transaction/
|-- repository/
|   |-- asset/
|   |-- asset_match/
|   |-- asset_risk/
|   |-- asset_vulnerability/
|   |-- audit/
|   |-- provider_usage/
|   |-- user/
|   `-- vulnerability/
`-- service/
    |-- ai/
    |-- asset/
    |-- asset_match/
    |-- asset_risk/
    |-- asset_vulnerability/
    |-- audit/
    |-- text_generation/
    |-- user/
    `-- vulnerability/
```

### Backend conventions

- Controllers handle HTTP binding and response formatting.
- Services handle business validation, authorization, and use-case orchestration.
- Services coordinate external providers; the AI diagnostic provider and prompt workflow lives in `api/service/ai`.
- Repositories handle GORM/database access only.
- Services request atomic transactions through `api/platform/transaction`; GORM transaction mechanics remain in `api/platform/db`.
- DTOs are separated from domain models and live with the controller component that owns the HTTP contract, with only shared response/error DTOs in `api/controller/shared`.
- Controller route registration lives in component `*_routes.go` files.
- Non-entrypoint support code lives in component `*_support.go` files so primary controller, service, repository, middleware, and external client files stay focused.
- Model files are grouped by domain: `asset.go` owns asset, assessment, and asset-vulnerability persistence models; `user.go` owns user and refresh-session persistence models.
- `platform/runtime` owns application wiring and server startup; `main.go` delegates to runtime and stays small.
- `platform` owns runtime infrastructure such as configuration, local bootstrap seed data, database setup/migrations, request context, and startup composition.
- `common` stays narrow: secure ID/token helpers and JWT primitives. Asset-risk calculation and affected-asset refreshes live in `api/service/asset_risk` and `api/repository/asset_risk`.
- Repository, service, external, and controller packages own their layer-specific error contracts where those boundaries need stable errors.
- Repository, service, and external packages expose component-local interfaces only when they are real layer boundaries or useful test seams.
- API collection files live under `BlackRadar/tests/`.
- Admin permissions must not be exposed through client-controlled registration.

## API Summary

### Implemented routes

Authentication

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`

Registration accepts `fullName`, `username`, `email`, and `password`. Authenticated responses return the full name with the user summary.

Assets

- `GET /api/assets`
- `GET /api/assets/{id}`
- `POST /api/assets`
- `PUT /api/assets/{id}`
- `DELETE /api/assets/{id}`

`POST /api/assets` also supports backend AI-assisted asset creation when the request uses `aiMode` with `rawText`.

Vulnerabilities

- `GET /api/vulnerabilities`
- `GET /api/vulnerabilities/{id}`
- `POST /api/vulnerabilities` with `cveId`, `title`, `severity`, `description`, and `status`
- `PUT /api/vulnerabilities/{id}`
- `DELETE /api/vulnerabilities/{id}`

Assignment

- `POST /api/assets/{assetId}/vulnerabilities/{vulnerabilityId}`
- `POST /api/assets/{assetId}/match-cpe/vulnerabilities`
- `DELETE /api/assets/{assetId}/vulnerabilities/{vulnerabilityId}`

NVD

- `GET /api/nvd/cves/{cveId}`

AI diagnostics

- `GET /api/ai/test`
- `POST /api/ai/message`

## Data Model Direction

The current model is centered on:

- `users`
- `assets`
- `vulnerabilities`
- `asset_vulnerabilities`
- `refresh_sessions`

Users own their assets and vulnerabilities directly in the current implementation. Assets keep core inventory fields plus `riskLevel`, `criticality`, and a linked assessment record. `riskLevel` stays null until vulnerabilities are attached and the backend derives a value from their severities. The linked `asset_assessments` data holds `riskScore`, product fingerprint, selected CPE, confidence, review status, review notes, candidate count, and match timestamp.

### Asset model goals

Assets should capture both business inventory and product fingerprint metadata:

- name
- type
- vendor
- product
- version
- operating system
- owner
- criticality
- linked assessment data plus asset risk level
- CPE metadata and sync timestamps

## Security Approach

BlackRadar Security Platform is organized around strong backend controls and safe external integration.

Security principles:

- BCrypt password hashing
- JWT access tokens with short lifetimes
- server-side refresh-token sessions
- logout-driven session revocation
- server-side authorization enforcement
- admin permissions enforced in middleware
- DTO-based request and response handling
- service-owned transaction boundaries implemented through the platform transaction runner
- backend-only AI and external service keys
- local persistence of vulnerability data over live UI lookups
- soft-delete support for records that need recovery, retention, or forensic auditability
- safe error handling without secret leakage
- request sanitization and validation before processing
- rate limiting for AI-assisted matching and diagnostic routes

AI-specific guidance:

- keep OpenAI API keys server-side
- use AI as an assist layer, not a source of truth
- validate JSON model output before using it
- minimize outbound prompt payloads and redact common secrets and direct identifiers before provider calls
- require review for ambiguous or low-confidence matches
- ground chatbot answers in local data

## Documentation

- `README.md`: product overview and setup guidance
- `BlackRadar/docs/`: feature documentation covering what, why, how, ownership, security, and current limitations
- `BlackRadar/docs/infrastructure.md`: current Docker Compose, container, network, and persistence topology
- `BlackRadar/docs/asset-risk.md`: backend risk calculation and refresh workflow
- `BlackRadar/docs/ci-cd.md`: current GitHub Actions validation checks and build artifacts
- `.agents/skills/architecture/SKILL.md`: technical architecture and implementation direction
- `.agents/skills/clean-code/SKILL.md`: naming, structure, and implementation conventions
- `.agents/skills/roadmap/SKILL.md`: product roadmap, planned features, and sequencing notes
- `.agents/skills/security/SKILL.md`: mandatory security policy and secure-coding rules for this repository
- `AGENTS.md`: repository-specific assistant instructions

## Planned Extensions

Future work documented in `.agents/skills/roadmap/SKILL.md` includes:

- future API areas such as `GET /api/organizations`, `POST /api/organizations/switch`, `POST /api/assets/{id}/chat`, `POST /api/sync/nvd`, `GET /api/alerts`, `PATCH /api/alerts/{id}/acknowledge`, and dashboard summary endpoints
- future organization listing and active organization switching
- future application-aware scoping on top of a server-side ownership boundary
- future multi-organization membership with active organization switching
- frontend workflows for AI-assisted asset creation, CPE review, and vulnerability attachment
- asset-scoped chatbot and guided security answers
- remediation workflows, work orders, checklist items, and exceptions
- alerting and CVE refresh services
- dashboard analytics and risk trend reporting
- future organization-aware API and UI flows for assets, vulnerabilities, and memberships
- future data model expansions such as alerts, work orders, work order checklist items, vulnerability exceptions, remediation entries, comments, optional chat sessions and chat messages, sync history records, future organization membership and active-organization records, and audit and notification records for sensitive actions
- HTTPS/TLS enforcement with certificate handling at the deployment boundary
- backend-issued internal service certificates for privileged `/internal` service authentication
- protected GitHub Actions release environments and deployment
- full Docker integration for frontend, backend, and services
- later AWS deployment foundation using ECR, ECS/Fargate or EC2, RDS, ALB/ACM, Secrets Manager, CloudWatch, and EventBridge
- later AWS edge controls such as WAF, ALB throttling, or CloudFront-style protection layered on top of backend limits
- later AWS single-tenant deployment option for dedicated organizational instances
