# 🏗️ Infrastructure

## 🧭 Overview

BlackRadar currently uses Docker Compose as its local full-stack runtime. The stack starts PostgreSQL, the Go backend, and the Angular development server as separate services connected through a private Compose network. The backend remains the application boundary for database access and external providers.

## 🗺️ Current Topology

```text
Browser
  |
  v
Angular development server :4200
  |
  v
Go Gin/GORM backend :8080
  |                 \
  v                  v
PostgreSQL :5432   NVD / OpenAI APIs
```

The browser uses the backend API at `http://localhost:8080/api` in the development environment. It does not connect directly to PostgreSQL, NVD, or OpenAI.

## 🐳 Compose Services

The root `docker-compose.yml` defines three current services:

- **PostgreSQL:** Uses the `postgres:16` image, reads database credentials from the root `.env` file, exposes the configured host port, and stores data in the named `postgres_data` volume.
- **Backend:** Builds from `BlackRadar/Dockerfile`, runs as the unprivileged `blackradar` user, uses a read-only root filesystem with dropped Linux capabilities, waits for PostgreSQL's health check, exposes port `8080`, and receives the Compose database hostname `postgres` through its environment.
- **Frontend:** Uses `node:22-alpine`, mounts `BlackRadar/ui`, keeps dependencies in the `frontend_node_modules` volume, and runs Angular's development server on port `4200`. Dependencies are installed explicitly with `docker compose run --rm frontend npm ci`, not during every service startup.

The frontend depends on the backend for startup ordering. The backend exposes `/api/health` for a basic process check and `/api/ready` for database readiness. These checks do not replace request-level error handling when a dependency is unavailable.

## 🔄 Startup Flow

1. Compose starts PostgreSQL and runs `pg_isready` until the configured database is accepting connections.
2. Compose starts the backend after the database health check succeeds.
3. The backend connects using the internal service name `postgres`, initializes the current runtime schema through GORM, and listens on port `8080`.
4. Compose starts the Angular development server, which serves the UI on port `4200`.
5. Browser requests travel from Angular to the backend API, while backend-owned code handles PostgreSQL and external provider calls.

## 🔐 Configuration And Trust

The root `.env` file supplies local database and provider configuration to Compose and the backend. Compose does not enable bootstrap data unless `BOOTSTRAP_DEV_DATA=true` is explicitly configured. Secrets and provider credentials belong on the backend side of the boundary. They must not be placed in Angular environment files or exposed through browser responses.

The Compose network allows the backend to resolve PostgreSQL as `postgres`. The browser-facing ports are host development ports, not a production security boundary. Production deployment requires an explicit network, TLS, secret-management, logging, and access-control design.

When the Go backend is placed behind a reverse proxy, set `TRUSTED_PROXY_CIDRS` to the proxy IP addresses or CIDR ranges, separated by commas. Gin only accepts `X-Forwarded-For` and related headers from those configured networks; leaving the setting empty disables forwarded-client-IP trust. This boundary is important because authentication rate limiting uses the resolved client IP. Never configure `0.0.0.0/0` or `::/0` as a convenience value.

## 💾 Persistence And Lifecycle

PostgreSQL data persists in the named `postgres_data` volume across container recreation. The frontend dependency volume prevents repeated package installation from changing the source tree. Removing the database volume destroys local database state and should be treated as a destructive development operation.

The backend image uses a multi-stage build: Go dependencies and compilation occur in a Go build image, then the compiled binary and CA certificates are copied into a smaller Alpine runtime image. The runtime image uses a non-root user. Compose additionally drops all Linux capabilities, prevents privilege escalation, and makes the backend root filesystem read-only while allowing `/tmp` through a restricted tmpfs. The current frontend Compose service is development-oriented and does not build a production static bundle.

## 🎭 Walkthrough: Alice Uses The Local Stack

- **Who:** Alice uses the browser; Bob is another authenticated user whose data remains separated by backend authorization.
- **What:** Alice opens the Angular application and requests one of her assets.
- **When:** The local Compose stack is running and the browser calls the API.
- **Where:** Angular serves port `4200`, the backend handles port `8080`, and PostgreSQL is reached internally through `postgres:5432`.
- **Why:** Separate services keep UI delivery, application rules, and persistence responsibilities explicit while allowing the full system to run locally.
- **How:** The browser sends an authenticated API request, the backend derives Alice's scope, the repository queries PostgreSQL, and the response returns through the backend without exposing database or provider access to Alice's browser.

## 🚧 Current And Planned Boundaries

Current infrastructure is optimized for local development and testable service separation. It does not yet provide a production deployment profile, verified image digest pinning, HTTPS termination, managed secrets, versioned migrations, a production frontend image, or certificate-authenticated internal services. Those concerns are deployment hardening rather than current Compose behavior.

## 🔑 Key Terms

- **Docker Compose:** The local orchestration file that starts the related containers.
- **Service name:** The internal Compose DNS name used for service-to-service connections.
- **Health check:** A command used to determine whether a dependency is ready.
- **Named volume:** Persistent Docker-managed storage independent of a container's lifecycle.
- **Multi-stage build:** A Docker build that separates compilation dependencies from the runtime image.
- **Runtime schema:** The database structure currently provisioned by backend startup behavior.
