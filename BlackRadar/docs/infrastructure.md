# 🏗️ Infrastructure

## 🧭 Overview

BlackRadar uses Docker Compose as its local full-stack runtime. The stack runs PostgreSQL, the Go backend, and the Angular development server as separate services on a private Compose network. That separation matters: the backend stays the boundary for database access and external providers, while the browser only talks to the backend API.

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

In development, the browser uses `http://localhost:8080/api`. It never connects directly to PostgreSQL, NVD, or OpenAI.

## 🐳 Compose Services

The root `docker-compose.yml` defines three services.

PostgreSQL uses the `postgres:16` image, reads credentials from the root `.env` file, stays reachable only through the private Compose network, and stores data in the named `postgres_data` volume.

The backend builds from `BlackRadar/Dockerfile`, runs as the unprivileged `blackradar` user, uses a read-only root filesystem with dropped Linux capabilities, waits for PostgreSQL readiness, exposes port `8080`, and receives the Compose database host name `postgres` through its environment.

The frontend uses `node:22-alpine`, mounts `BlackRadar/ui`, keeps dependencies in the `frontend_node_modules` volume, and runs Angular’s development server on port `4200`. Dependencies are installed explicitly with `docker compose run --rm frontend npm ci`, not during every service startup.

The backend exposes `/api/health` for a basic process check and `/api/ready` for database readiness. Those endpoints help with startup and monitoring, but they do not replace request-level error handling when a dependency is unavailable.

## 🔄 Startup Flow

1. Compose starts PostgreSQL and waits for `pg_isready` to report that the database is accepting connections.
2. Compose starts the backend after that health check passes.
3. The backend connects through the internal service name `postgres`, runs the current runtime schema setup through GORM, and listens on port `8080`.
4. Compose starts the Angular development server, which serves the UI on port `4200`.
5. Browser requests flow from Angular to the backend, and backend-owned code handles PostgreSQL and external provider calls.

## 🔐 Configuration And Trust

The root `.env` file supplies local database and provider configuration to Compose and the backend. Compose does not enable bootstrap data unless `BOOTSTRAP_DEV_DATA=true` is explicitly set. Secrets and provider credentials belong on the backend side of the boundary. They do not belong in Angular environment files or browser responses.

The Compose network lets the backend resolve PostgreSQL as `postgres`; PostgreSQL is not published to the host. The browser-facing ports are development ports, not a production security boundary. Production still needs explicit network, TLS, secret-management, logging, and access-control design.

When the Go backend sits behind a reverse proxy, `TRUSTED_PROXY_CIDRS` must list the proxy IPs or CIDR ranges, separated by commas. Gin only trusts forwarded client IP headers from those networks. Leaving the setting empty disables that trust. This matters because authentication rate limiting uses the resolved client IP. `0.0.0.0/0` and `::/0` are not safe convenience values.

## 💾 Persistence And Lifecycle

PostgreSQL data persists in the named `postgres_data` volume across container recreation. The frontend dependency volume prevents repeated package installation from changing the source tree. Removing the database volume destroys local database state, so it should be treated as a destructive development action.

The backend image uses a multi-stage build. Go dependencies and compilation happen in a Go build image, and the compiled binary plus CA certificates are copied into a smaller Alpine runtime image. The runtime image uses a non-root user. Compose also drops Linux capabilities, prevents privilege escalation, and makes the backend root filesystem read-only while allowing `/tmp` through a restricted tmpfs. The frontend service is still development-oriented and does not build a production static bundle.

## 🎭 Walkthrough: Alice Uses The Local Stack

- **Who:** Alice uses the browser; Bob is another authenticated user whose data remains separated by backend authorization.
- **What:** Alice opens the Angular application and requests one of her assets.
- **When:** The local Compose stack is running and the browser calls the API.
- **Where:** Angular serves port `4200`, the backend handles port `8080`, and PostgreSQL is reached internally through `postgres:5432`.
- **Why:** Separate services keep UI delivery, application rules, and persistence responsibilities explicit while still letting the full system run locally.
- **How:** The browser sends an authenticated API request, the backend derives Alice’s scope, the repository queries PostgreSQL, and the response returns through the backend without exposing database or provider access to Alice’s browser.

## 🚧 Current And Planned Boundaries

Current infrastructure is designed for local development and testable service separation. It does not yet provide a production deployment profile, verified image digest pinning, HTTPS termination, managed secrets, versioned migrations, a production frontend image, or certificate-authenticated internal services. Those concerns belong to deployment hardening, not current Compose behavior.

## 🔑 Key Terms

- **Docker Compose:** The local orchestration file that starts the related containers.
- **Service name:** The internal Compose DNS name used for service-to-service connections.
- **Health check:** A command used to determine whether a dependency is ready.
- **Named volume:** Persistent Docker-managed storage independent of a container’s lifecycle.
- **Multi-stage build:** A Docker build that separates compilation dependencies from the runtime image.
- **Runtime schema:** The database structure currently provisioned by backend startup behavior.
