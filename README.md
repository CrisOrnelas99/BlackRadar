# SecureOps

SecureOps is a focused cybersecurity asset risk platform. It combines asset inventory, vulnerability intelligence, and AI-assisted workflows to help teams understand risk across organizations, applications, home networks, and imported asset inventories.

For implementation details and agent rules, use `ARCHITECTURE.md`, `CLEANCODE.md`, and `SECURITY.md` together. `README.md` stays at the product and setup level.

## Table of Contents

- [What This Project Is](#what-this-project-is)
- [Architecture](#architecture)
- [Current Capabilities](#current-capabilities)
- [Planned Extensions](#planned-extensions)
- [Repository Layout](#repository-layout)
- [Getting Started](#getting-started)
- [API Summary](#api-summary)
- [Data Model Direction](#data-model-direction)
- [Security Approach](#security-approach)
- [Security Guidance for Coding Agents](#security-guidance-for-coding-agents)
- [Documentation](#documentation)

## What This Project Is

SecureOps is designed as a practical, developer-friendly security application rather than a full enterprise SIEM.
It demonstrates how a secure backend trust boundary, external vulnerability data, and AI-assisted ingestion can work together in one system.

Key capabilities include:

- asset inventory with product-aware metadata
- vulnerability tracking and asset-to-vulnerability assignment
- organization-scoped data separation
- backend-enforced authorization and security controls
- backend rate limiting on auth and NVD lookup endpoints
- short-lived access tokens with server-side refresh-token sessions
- backend OpenAI-assisted asset creation, CPE matching, and NVD vulnerability attachment
- planned organization switching, workflow, alerting, frontend AI flows, and chatbot features listed below

The platform supports multiple inventory contexts, including organization portfolios, applications, home networks, and imported raw asset lists.

## Architecture

SecureOps is intentionally designed with clear component separation.
The backend is the primary security boundary and owner of authorization, persistence, external integration, and AI orchestration.
See `ARCHITECTURE.md` for the technical layout and `CLEANCODE.md` for code-structure rules that keep the implementation consistent with that layout.

- Angular frontend: UI, authentication, asset and vulnerability workflows, chat UX.
- Go Gin/GORM backend: API, authentication, business logic, data orchestration, NVD/AI integration.
- PostgreSQL: persistent storage for users, assets, vulnerabilities, and future workflow state.
- Focused services: planned narrow services for alerting and CVE refresh.
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
  |
  +--> alert-service-go (planned)
  |
  +--> cve-sync-service-go (planned)
  +--> NVD / NIST APIs
  `--> OpenAI API
```

### Design principles

- Backend is the main security and trust boundary.
- Frontend never calls NVD, AI providers, or internal services directly.
- Backend enforces validation, authorization, and DTO mapping.
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
- asset-to-vulnerability assignment by CVE ID
- NVD CPE candidate search support
- backend OpenAI provider configuration and text-generation boundary
- AI-assisted asset creation from raw text through the backend
- AI-assisted asset product fingerprinting and CPE ranking
- persisted asset assessment metadata, including risk score, product fingerprint, selected CPE, confidence, review status, review notes, candidate count, and matched timestamp
- CPE-based NVD CVE lookup and bounded vulnerability attachment to assets
- admin-only AI diagnostic endpoints
- organization-aware registration and tenant membership
- controller → service → repository layering
- GORM AutoMigrate provisioning
- Docker Compose support for PostgreSQL and backend
- Angular frontend project scaffold under `frontend-angular/`

## Planned Extensions

Future work documented in `ARCHITECTURE.md` includes:

- organization listing and active organization switching
- application-aware scoping on top of the organization boundary
- multi-organization membership with active organization switching
- frontend workflows for AI-assisted asset creation, CPE review, and vulnerability attachment
- asset-scoped chatbot and guided security answers
- remediation workflows, work orders, checklist items, and exceptions
- alerting and CVE refresh services
- dashboard analytics and risk trend reporting
- organization-aware API and UI flows for assets, vulnerabilities, and memberships
- HTTPS/TLS enforcement with certificate handling at the deployment boundary
- GitHub Actions CI/CD pipeline for tests, builds, and protected releases
- full Docker integration for frontend, backend, and services
- later AWS deployment foundation using ECR, ECS/Fargate or EC2, RDS, ALB/ACM, Secrets Manager, CloudWatch, and EventBridge
- later AWS edge controls such as WAF, ALB throttling, or CloudFront-style protection layered on top of backend limits
- later AWS single-tenant deployment option for dedicated organizational instances

## Repository Layout

```text
AssetManagementRisk/
|-- backend-Go/
|-- frontend-angular/
|-- docker-compose.yml
|-- .env
|-- README.md
|-- CLEANCODE.md
|-- ARCHITECTURE.md
|-- SECURITY.md
`-- AGENTS.md
```

Inside `backend-Go/`:

```text
backend-Go/
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
|-- Dockerfile
|-- go.mod
|-- go.sum
`-- main.go
```

### Backend conventions

- Controllers handle HTTP binding and response formatting.
- Services handle business validation, authorization, and use-case orchestration.
- Repositories handle GORM/database access only.
- DTOs are separated from domain models.
- `errors.go` files contain sentinel errors and error type declarations.
- Admin permissions must not be exposed through client-controlled registration.

## Getting Started

### Requirements

- Docker Desktop
- Node.js for Angular frontend work
- Go for backend development or local builds

### Starting the current backend stack

The current `docker-compose.yml` includes:

- `postgres`
- `backend`

Start the full Compose stack with:

```bash
docker compose up --build
```

The backend container starts with `BOOTSTRAP_DEV_DATA=true`, so the seeded `system_admin` test account is available after a fresh compose start.
That bootstrap account belongs to the `admin_home` organization.

Default endpoints:

- backend: `http://localhost:8080`
- PostgreSQL: mapped from `${POSTGRES_PORT}` to container `5432`

For backend development, it is often simpler to run PostgreSQL in Docker and the Go backend directly from the local shell.
This keeps rebuilds fast while still using the same database container.

From the repository root:

```powershell
$env:POSTGRES_PORT = '15432'
docker compose up -d postgres
docker compose ps
```

Use `15432` when another PostgreSQL process is already using local port `5432`.
The `docker compose ps` output should show `15432->5432/tcp`.

Then run the backend from `backend-Go/`:

```powershell
cd backend-Go
$env:DATABASE_URL = 'postgres://secureops_user:s5e4c3u2r1e@127.0.0.1:15432/secureops'
$env:JWT_SECRET = 't1h2i3s4I5s6A7R8a9n0d1o2m3S4e5c6r7e8t'
$env:BOOTSTRAP_DEV_DATA = 'true'
go run .
```

When using local `go run .`, Go reads environment variables from the PowerShell session.
It does not automatically load the root `.env` file.
Docker Compose reads `.env` for containers.

`BOOTSTRAP_DEV_DATA=true` is optional. When enabled in development, startup creates or updates a local test setup:

- admin username: `system_admin`
- email: `test@gmail.com`
- organization: `admin_home`
- password: `Password123!`
- one test device asset
- one assigned example vulnerability: `CVE-2021-44228`

Registration also requires an organization name so new users are bound to the correct tenant boundary at signup.

The bootstrap flag is rejected in production mode.

If port `8080` is already in use, stop the old local backend process before restarting:

```powershell
netstat -ano | findstr ":8080"
Stop-Process -Id <PID> -Force
```

### Frontend status

The Angular frontend lives in `frontend-angular/` but is not yet wired into Docker Compose in the current repository state.
Treat it as work-in-progress rather than production ready.

### Environment configuration

This project uses a local `.env` file for development configuration.
Typical values include:

- PostgreSQL database host, port, name, user, password
- JWT secret and expiration
- NVD API key
- OpenAI API key
- internal service URLs

Important:

- do not commit secrets
- do not expose API keys to the frontend
- keep `.env` local to development

## API Summary

### Implemented routes

Authentication
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`

Registration accepts `username`, `email`, `organization`, and `password`.

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

### Planned API areas

- `GET /api/organizations`
- `POST /api/organizations/switch`
- `POST /api/assets/{id}/chat`
- asset alert endpoints
- organization-scoped work order workflows
- comment and remediation endpoints
- checklist and exception endpoints for remediation workflows
- `POST /api/sync/nvd`
- `GET /api/alerts`
- `PATCH /api/alerts/{id}/acknowledge`
- dashboard summary endpoints
- health and maintenance endpoints for background services

## Data Model Direction

The current model is centered on:

- `organizations`
- `users`
- `assets`
- `vulnerabilities`
- `asset_vulnerabilities`
- `refresh_sessions`

Users, assets, and vulnerabilities are scoped to one organization.
Assets keep core inventory fields plus `riskLevel`, `criticality`, and a linked assessment record. `riskLevel` stays null until vulnerabilities are attached and the backend derives a value from their severities. The linked `asset_assessments` data holds `riskScore`, product fingerprint, selected CPE, confidence, review status, review notes, candidate count, and match timestamp.

Future expansions may include:

- `alerts`
- `work_orders`
- `work_order_checklist_items`
- `vulnerability_exceptions`
- `remediation_entries`
- `comments`
- optional `chat_sessions` and `chat_messages`
- sync history records
- organization membership and active-organization records
- audit and notification records for sensitive actions

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

SecureOps is organized around strong backend controls and safe external integration.

Security principles:

- BCrypt password hashing
- JWT access tokens with short lifetimes
- server-side refresh-token sessions
- logout-driven session revocation
- server-side authorization enforcement
- admin permissions enforced in middleware
- DTO-based request and response handling
- backend-only AI and external service keys
- local persistence of vulnerability data over live UI lookups
- safe error handling without secret leakage
- request sanitization and validation before processing
- rate limiting for AI-assisted matching and diagnostic routes

AI-specific guidance:

- keep OpenAI API keys server-side
- use AI as an assist layer, not a source of truth
- validate JSON model output before using it
- require review for ambiguous or low-confidence matches
- ground chatbot answers in local data

## Security Guidance for Coding Agents

`SECURITY.md` is the mandatory security reference for humans and coding agents working in this repository. Read it before making changes that affect authentication, authorization, validation, secrets, dependencies, Docker, PostgreSQL, external integrations, Angular rendering, Go/Gin/GORM behavior, or AI-assisted workflows.

`ARCHITECTURE.md` defines the system layout and trust boundaries. `CLEANCODE.md` defines naming, structure, and implementation conventions. `README.md` should not override either of those files.

## Documentation

- `README.md`: product overview and setup guidance
- `ARCHITECTURE.md`: technical architecture and implementation direction
- `CLEANCODE.md`: naming, structure, and implementation conventions
- `SECURITY.md`: mandatory security policy and secure-coding rules for this repository
- `AGENTS.md`: repository-specific assistant instructions - Creator only
