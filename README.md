# SecureOps Lite

SecureOps Lite is a focused cybersecurity asset risk platform. It combines asset inventory, vulnerability intelligence, and AI-assisted workflows to help teams understand risk across organizations, applications, home networks, and imported asset inventories.

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
- [Documentation](#documentation)

## What This Project Is

SecureOps Lite is designed as a practical, developer-friendly security application rather than a full enterprise SIEM.
It demonstrates how a secure backend trust boundary, external vulnerability data, and AI-assisted ingestion can work together in one system.

Key capabilities include:

- asset inventory with product-aware metadata
- vulnerability tracking and asset-to-vulnerability assignment
- backend-enforced authorization and security controls
- planned vulnerability intelligence and AI-assisted workflows listed below

The platform supports multiple inventory contexts, including organization portfolios, applications, home networks, and imported raw asset lists.

## Architecture

SecureOps Lite is intentionally designed with clear component separation.
The backend is the primary security boundary and owner of authorization, persistence, external integration, and AI orchestration.

- Angular frontend: UI, authentication, asset and vulnerability workflows, chat UX.
- Go Gin/GORM backend: API, authentication, business logic, data orchestration, NVD/AI integration.
- PostgreSQL: persistent storage for users, assets, vulnerabilities, and future workflow state.
- Focused services: planned narrow services for alerting and CVE refresh.

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
  `--> AI provider API
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
- JWT-based authentication
- permission middleware support
- asset CRUD API and models
- vulnerability CRUD API and models
- asset-to-vulnerability assignment endpoints
- controller → service → repository layering
- GORM AutoMigrate provisioning
- Docker Compose support for PostgreSQL and backend
- Angular frontend project scaffold under `frontend-angular/`

## Planned Extensions

Future work documented in `architecture.md` and `Roadmap.md` includes:

- organization- and application-aware multi-tenant scoping
- asset fingerprinting with vendor/product/version metadata
- NVD/NIST CVE import and local vulnerability persistence
- AI-assisted asset ingestion and relevance review
- asset-scoped chatbot and guided security answers
- remediation workflows, work orders, checklist items, and exceptions
- alerting and CVE refresh services
- dashboard analytics and risk trend reporting
- full Docker integration for frontend, backend, and services
- later AWS/cloud integration

## Repository Layout

```text
AssetManagementRisk/
|-- backend-Go/
|-- frontend-angular/
|-- docker-compose.yml
|-- .env
|-- README.md
|-- Roadmap.md
|-- architecture.md
`-- Agents.md
```

Inside `backend-Go/main/`:

```text
backend-Go/main/
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

Start the stack with:

```bash
docker compose up --build
```

Default endpoints:

- backend: `http://localhost:8080`
- PostgreSQL: mapped from `${POSTGRES_PORT}` to container `5432`

### Frontend status

The Angular frontend lives in `frontend-angular/` but is not yet wired into Docker Compose in the current repository state.
Treat it as work-in-progress rather than production ready.

### Environment configuration

This project uses a local `.env` file for development configuration.
Typical values include:

- PostgreSQL database host, port, name, user, password
- JWT secret and expiration
- NVD API key
- AI provider API key
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

Assets
- `GET /api/assets`
- `GET /api/assets/{id}`
- `POST /api/assets`
- `PUT /api/assets/{id}`
- `DELETE /api/assets/{id}`

Vulnerabilities
- `GET /api/vulnerabilities`
- `GET /api/vulnerabilities/{id}`
- `POST /api/vulnerabilities`
- `PUT /api/vulnerabilities/{id}`
- `DELETE /api/vulnerabilities/{id}`

Assignment
- `POST /api/assets/{assetId}/vulnerabilities/{vulnerabilityId}`
- `DELETE /api/assets/{assetId}/vulnerabilities/{vulnerabilityId}`

### Planned API areas

- `POST /api/assets/{id}/import-nvd-vulnerabilities`
- `POST /api/assets/{id}/chat`
- asset alert endpoints
- organization-scoped work order workflows
- comment and remediation endpoints
- `POST /api/sync/nvd`
- `GET /api/alerts`
- `PATCH /api/alerts/{id}/acknowledge`

## Data Model Direction

The current model is centered on:

- `organizations`
- `users`
- `assets`
- `vulnerabilities`
- `asset_vulnerabilities`

Future expansions may include:

- `alerts`
- `work_orders`
- `work_order_checklist_items`
- `vulnerability_exceptions`
- `remediation_entries`
- `comments`
- optional `chat_sessions` and `chat_messages`
- sync history records

### Asset model goals

Assets should capture both business inventory and product fingerprint metadata:

- name
- type
- vendor
- product
- version
- operating system
- IP address
- owner
- criticality
- risk score / risk level
- CPE metadata and sync timestamps

## Security Approach

SecureOps Lite is organized around strong backend controls and safe external integration.

Security principles:

- BCrypt password hashing
- JWT-based backend authentication
- server-side authorization enforcement
- admin permissions enforced in middleware
- DTO-based request and response handling
- backend-only AI and external service keys
- local persistence of vulnerability data over live UI lookups
- safe error handling without secret leakage
- request sanitization and validation before processing

AI-specific guidance:

- keep AI provider keys server-side
- use AI as an assist layer, not a source of truth
- ground chatbot answers in local data
## Documentation

- `README.md`: product overview and setup guidance
- `architecture.md`: technical architecture and implementation direction
- `Roadmap.md`: planned feature sequence - Creator only
- `Agents.md`: repository-specific assistant instructions - Creator only
