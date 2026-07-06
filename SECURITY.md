# SECURITY.md

## Purpose

This document is the mandatory security policy for humans and coding agents working on this application.

This repository is BlackRadar Security Platform, a business asset and vulnerability-management web application built with:

* Backend: Go, Gin, GORM, PostgreSQL, pgx, BCrypt, and JWT
* Frontend: Angular, Angular SSR, TypeScript, Node/Express, RxJS, and Vitest
* Local orchestration: Docker Compose with PostgreSQL and the Go backend
* External integrations: vulnerability and threat-data APIs, including NIST/NVD-style sources
* Future features may include focused Go services, remediation workflows, work orders, audit trails, collaboration, and OpenAI-backed AI/chat assistance.

Use this file with `README.md`, `ARCHITECTURE.md`, and `AGENTS.md`. When those files describe current implementation or planned behavior, this file defines the security rules that coding agents must preserve while working in this repo.

Security is a functional requirement. Do not trade security controls for speed, convenience, or passing tests.

**Baseline:** OWASP Top 10:2025 and OWASP ASVS 5 Level 2.
**Default behavior:** Treat all external input as untrusted. Enforce security on the server. Fail closed when authorization, validation, integrity, or safety is uncertain.

---

# 1. Mandatory Rules for Coding Agents

## 1.1 Read before changing

Before making a change, the coding agent must:

1. Read this file.
2. Review relevant routes, handlers, services, repositories, models, migrations, middleware, API contracts, environment configuration, CI/CD configuration, and tests.
3. Identify affected trust boundaries:

   * Browser to API
   * API to database
   * API to third-party services
   * Tenant to tenant
   * User role to privileged operation
   * CI/CD to deployed environment
4. State the security impact of the proposed change.
5. Preserve existing security controls unless the user explicitly approves changing them.

The agent may inspect local source files and perform read-only analysis without permission. It must ask first before actions that download, install, modify, delete, migrate, deploy, scan an external target, or use sensitive data.

## 1.2 Ask permission before risky actions

The coding agent must ask for explicit permission before it:

* Installs, downloads, imports, upgrades, removes, or replaces packages, modules, plugins, binaries, containers, or SDKs.
* Runs commands that contact the internet or modify dependency files, including `go get`, `go mod tidy`, `npm install`, `npm update`, `npm audit fix`, or package-manager commands with `--force`.
* Downloads external files, scripts, models, templates, datasets, database backups, or code from a URL.
* Runs scripts copied from the internet, especially shell pipelines such as `curl ... | sh`.
* Changes `go.mod`, `go.sum`, `package.json`, lockfiles, Dockerfiles, CI/CD workflows, deployment configuration, infrastructure configuration, or registry configuration.
* Creates, alters, runs, or rolls back database migrations.
* Deletes, bulk-updates, imports, exports, anonymizes, restores, or otherwise mutates production-like data.
* Connects to production, staging, cloud accounts, databases, external APIs, source-control secrets, or user accounts.
* Changes authentication, authorization, session handling, password handling, CORS, CSP, TLS, proxy trust, rate limits, audit logging, or security headers.
* Adds telemetry, analytics, third-party scripts, browser extensions, or AI services that could receive application or user data.
* Runs a vulnerability scan, DAST scan, fuzzing campaign, port scan, or penetration-testing activity against anything other than an authorized local environment.

When asking, state:

* What action is proposed
* Why it is needed
* The source and exact version
* Security impact
* Files or systems affected
* Rollback plan
* Whether the action changes lockfiles, schema, data, infrastructure, or external access

## 1.3 Never do these things

The coding agent must never:

* Commit, print, log, hardcode, or expose real secrets.
* Add credentials to source code, test fixtures, screenshots, documentation, Docker images, or client-side bundles.
* Disable TLS certificate verification, hostname verification, signature verification, CSRF protection, authorization checks, audit logging, input validation, or security tests to “make it work.”
* Use wildcard CORS with credentials.
* Store access tokens, refresh tokens, API keys, or session secrets in browser local storage.
* Trust authorization decisions made only by Angular or any browser code.
* Use user input to construct SQL, shell commands, file paths, URLs, sort fields, database column names, templates, regular expressions, or dynamic imports without strict validation or allowlisting.
* Use `fmt.Sprintf` or string concatenation to build GORM SQL conditions.
* Automatically run destructive commands, schema changes, dependency upgrades, or `npm audit fix --force`.
* Automatically send sensitive records to external AI tools, logging vendors, analytics tools, or third-party APIs.
* “Fix” a security finding by suppressing a scanner or weakening a control without written approval and a compensating control.
* Attempt to exploit a suspected vulnerability beyond the minimum safe proof needed to confirm it.

## 1.4 Security stop rule

Stop work and report the finding immediately when any of these are discovered:

* Cross-tenant data access
* Broken authorization or privilege escalation
* Hardcoded secrets or leaked credentials
* SQL injection, command injection, XSS, SSRF, path traversal, unsafe deserialization, or authentication bypass
* Sensitive data exposed through logs, API responses, errors, source maps, backups, or public storage
* Publicly reachable admin/debug endpoints
* Production database credentials used in local development
* A dependency with an actively exploitable critical vulnerability
* A change that would weaken a security control

Do not silently patch around these issues. Explain the risk, affected area, safe remediation, validation plan, and whether secrets must be rotated.

---

# 2. Security Architecture Rules

## 2.1 Multi-tenant isolation

An organization is a security boundary.

Assets, vulnerabilities, remediation plans, work orders, comments, audit events, attachments, users, and chatbot context must always belong to one organization.

Rules:

* Derive the active organization/tenant from authenticated server-side context.
* When registration accepts an organization name, resolve or create the organization server-side and bind the new user to that organization. Never accept a client-supplied `organization_id`.
* Never trust `organization_id`, `tenant_id`, `role`, or `user_id` supplied in request bodies, query parameters, headers, cookies, or Angular state.
* Every database query involving tenant-owned data must filter by the authenticated tenant.
* Verify both tenant membership and role/permission before reading or modifying a record.
* Do not rely on a frontend route guard as authorization.
* Use separate request DTOs, domain models, and response DTOs. Do not bind API requests directly into GORM persistence models.
* Add negative tests proving that a user from Organization A cannot access Organization B records, even when they know or guess an ID.

Example repository rule:

```go
// Every tenant-owned query begins from a tenant-scoped database handle.
db.Where("organization_id = ?", authContext.OrganizationID)
```

Tenant scoping is required for reads, updates, deletes, exports, background jobs, search, attachments, audit trails, chatbot retrieval, and workflow actions.

## 2.2 Server-side authorization model

Use a centralized authorization policy.

Suggested roles:

* `platform_admin`: limited internal platform operations only
* `organization_admin`: organization configuration, membership, high-risk actions
* `security_manager`: vulnerability/workflow approval and reporting
* `security_analyst`: asset and vulnerability work
* `viewer`: read-only access

Rules:

* Deny by default.
* Check authorization on every API endpoint and every object access.
* Enforce record ownership and tenant membership, not only role names.
* Require elevated permission or re-authentication for destructive actions, exports, organization settings, user management, integration settings, and workflow overrides.
* Keep privileged actions server-side and audit them.
* Do not send hidden fields such as `is_admin`, `organization_id`, `owner_id`, `status`, or approval flags from the browser as trusted input.

## 2.3 Data classification

Classify data before storing or integrating it:

* **Secret:** passwords, API keys, JWT signing keys, database credentials, OAuth client secrets.
* **Sensitive:** user email addresses, tenant information, assets, IP addresses, CVE remediation notes, work orders, audit logs, attachments.
* **Internal:** product configuration, non-sensitive operational metadata.
* **Public:** intentionally public documentation only.

Rules:

* Do not store sensitive data unless needed.
* Return the minimum fields needed by each API response.
* Redact secrets and sensitive fields from logs.
* Use least-privilege access for database accounts, cloud roles, API tokens, and CI/CD credentials.
* Define retention and deletion rules for attachments, logs, audit data, and exports.

## 2.4 Token and session handling

This application uses JWT access tokens together with server-side refresh-token sessions.

Rules:

* Access tokens must be short-lived.
* Refresh tokens must be validated against server-side session state.
* Logout must revoke the stored session, not just clear a client-side value.
* Protected requests must fail closed if the token session is missing or revoked.
* Refresh-token rotation must revoke the old session and issue a new session identifier.
* Do not store refresh tokens in browser local storage.
* Do not treat a valid access token as sufficient if the server-side session has been revoked.

Implementation note:

* Login issues both an access token and a refresh token.
* Login and refresh responses include explicit `tokenExpiresAt` and `refreshTokenExpiresAt` timestamps.
* The access token is bound to a session ID and is checked against the refresh-session table on protected requests.
* Refresh requests rotate the session and return a new token pair.
* Logout revokes the refresh session and invalidates the paired access token on subsequent protected requests.

## 2.5 Cloud deployment rules

When the application is deployed to AWS or another cloud provider, keep these rules:

* Terminate HTTPS with a trusted certificate at the load balancer or server boundary.
* Keep databases private; do not expose RDS or equivalent databases publicly.
* Store secrets in managed secret storage such as AWS Secrets Manager or SSM Parameter Store.
* Limit IAM permissions to the minimum set of resources and actions required.
* Expose only the public edge such as an ALB; keep backend and database services on private networking.
* Send logs to a managed logging service such as CloudWatch without secrets.
* Preserve server-side authorization, validation, and session checks exactly as in local deployments.
* Prefer structured logs for audit and request events so security fields can be filtered without exposing payloads.
* Keep application-level rate limiting authoritative for auth and NVD lookup paths; use AWS WAF/ALB/CloudFront-style controls as a second layer only.
* When GitHub Actions is used for deployment, prefer OIDC-based cloud authentication over long-lived cloud access keys.

## 2.6 Internal service certificate authentication

Focused Go services that call privileged backend `/internal` routes must use certificate-based service authentication once those routes exist. Do not use browser JWTs, user passwords, shared static secrets, or long-lived bearer tokens for machine-to-machine privileged work.

Rules:

* Treat the Go backend as the internal certificate authority for this application unless a managed private CA is explicitly adopted later.
* Keep the backend CA private key in environment-specific secret management, not source code, documentation, Docker images, frontend bundles, logs, or test fixtures.
* Generate one-time handshake tokens with `crypto/rand`.
* Store handshake tokens hashed or otherwise protected at rest where practical.
* Make handshake tokens short-lived, single-use, scoped to the intended service identity, and auditable.
* Require an elevated configuration/admin permission before a user can create a handshake token.
* Require the internal service to generate its own key pair and submit a CSR; the backend must not create or return the service private key.
* Validate CSRs before signing, including expected key type, key size, subject fields, and requested service identity.
* Issue certificates with constrained validity periods, appropriate key usage values, and explicit service identity such as OU.
* Authenticate `/internal` requests by parsing the presented certificate, verifying the backend CA signature, checking expiration, and extracting the service identity.
* Authorize `/internal` routes separately after certificate authentication; a valid certificate must not imply access to every internal endpoint.
* Fail closed when the certificate is missing, malformed, expired, signed by an unknown CA, has an unexpected service identity, or is not allowed for the route.
* Log handshake creation, successful issuance, failed validation, and route denials without logging raw tokens, private keys, authorization headers, or full certificate bodies.
* Plan for revocation or emergency disablement of a service identity if a service key or certificate is suspected to be compromised.

## 2.7 Request-scoped database transactions

The Go backend uses request-scoped GORM transactions for HTTP request handling. This is a security and consistency control: a failed request must not leave partially written tenant, asset, vulnerability, session, workflow, or audit data behind.

Rules:

* Keep request transaction lifecycle ownership in middleware.
* Store the request transaction in the server-side request context, not in browser-controlled state.
* Commit only when the request completes successfully and no application errors were recorded.
* Roll back on failed status codes, recorded handler errors, failed transaction setup, and panics.
* Keep tenant authorization checks inside the same request flow that performs writes.
* Keep transactions short; avoid holding the request transaction open across slow external API calls when the work can be safely reordered.
* Do not start independent database transactions that bypass the request transaction for normal request-owned writes.
* Nested GORM transactions may be used intentionally for savepoint behavior, such as rolling back a focused inner operation while preserving the outer request transaction.
* Add or update tests when changing transaction commit/rollback behavior.

## 2.8 Soft-delete and retention rules

The implemented core models use GORM soft deletes where recovery, auditability, and forensic traceability matter. Delete endpoints still require the same authorization, audit, and review discipline as other high-impact actions.

Rules:

* Add explicit `deleted_at` metadata to records that need recovery, auditability, or forensic traceability.
* Use GORM soft deletes for normal application deletion paths instead of physical deletion.
* Restrict `Unscoped()` reads and hard deletes to approved cleanup, retention, recovery, or test utilities.
* Scope uniqueness rules to active records when identifiers may be reused after deletion.
* Manually filter soft-deleted join-table rows in joins and association queries where GORM does not add the predicate automatically.
* Ensure deleted users, disabled accounts, revoked sessions, and removed permissions cannot authenticate or authorize through stale JWT claims.
* Preserve tenant scoping on soft-deleted records; deleted data is still tenant data.
* Audit deletion, restoration, hard deletion, and retention cleanup actions.

## 2.9 Layered error handling

The Go backend uses repository, service, and controller error boundaries so lower-level implementation details do not leak into API responses.

Rules:

* Repository code must translate GORM, PostgreSQL, and constraint errors into repository sentinel errors.
* Service code must translate repository sentinel errors into service sentinel errors before returning to controllers.
* Service translation must preserve the underlying repository cause with Go error wrapping so `errors.Is` can still identify both layers.
* Controllers must map service errors to HTTP status codes and must not depend on GORM, PostgreSQL, or repository error types.
* `HandleError` is the shared controller response path for request failures.
* API clients receive safe JSON errors with stable error codes, user-facing messages, and request IDs.
* Logs may include the wrapped internal error chain, but responses must not expose stack traces, SQL text, passwords, tokens, certificate material, provider secrets, or raw upstream error bodies.
* Tests that change error translation must prove both the service error and preserved lower-level cause are detectable with `errors.Is`.

---

# 3. OWASP Top 10:2025 Requirements

## A01: Broken Access Control

### Risk

Users can access data or actions beyond their intended permissions. Common examples include IDOR/BOLA, cross-tenant access, missing admin checks, forced browsing, weak CORS, and insecure workflow actions.

### Application-specific examples

* A user changes `/assets/123` to `/assets/124` and sees another organization’s asset.
* A regular analyst marks a critical vulnerability as “accepted risk” without approval.
* An API accepts a request-body `organization_id` and uses it instead of the authenticated tenant.
* Angular hides an admin button, but the API endpoint has no server-side authorization check.
* A user manipulates a work-order status directly from `open` to `closed`, skipping remediation and verification.

### Mandatory controls

* Enforce authentication and authorization server-side for every endpoint.
* Scope every tenant-owned GORM query by `organization_id`.
* Check ownership and permission before update/delete operations.
* Treat soft-deleted records as inaccessible to normal application users unless an explicit administrative recovery or audit path authorizes access.
* Use policy functions or middleware shared across routes; do not duplicate authorization logic inconsistently.
* Return `403 Forbidden` for known-but-disallowed resources and avoid excessive detail that enables record enumeration.
* Use explicit CORS origin allowlists. Never allow arbitrary origins with credentials.
* Rate-limit sensitive endpoints and log authorization failures.
* Write authorization tests for every role and every protected object type.

### Agent checklist

* Does the handler derive identity and tenant from trusted auth context?
* Does the repository query filter by tenant?
* Is permission checked before every read, write, export, or workflow transition?
* Is the frontend only improving UX rather than being treated as the enforcement layer?
* Do tests include “wrong tenant,” “wrong role,” and “unauthenticated” cases?

---

## A02: Security Misconfiguration

### Risk

A secure application can be made insecure through unsafe defaults, debug settings, weak headers, exposed services, permissive CORS, public storage, or overly detailed errors.

### Mandatory controls

* Use separate development, test, staging, and production configurations.
* Never use production secrets in local development.
* Run Gin in production mode outside local development.
* Do not expose debug endpoints, stack traces, profiling endpoints, source maps, `.git`, backups, sample data, or admin interfaces publicly.
* Use a hardened reverse proxy/load balancer configuration.
* Configure trusted proxies explicitly. Do not trust arbitrary forwarding headers from the internet.
* Use explicit CORS origins, methods, headers, and credential settings.
* Send security headers appropriate to the deployed application:

  * `Content-Security-Policy`
  * `Strict-Transport-Security`
  * `X-Content-Type-Options: nosniff`
  * `Referrer-Policy`
  * `Permissions-Policy`
  * clickjacking protection through CSP `frame-ancestors`
* Return generic client errors while logging detailed server-side context.
* Restrict database, object storage, queues, and cache systems to private access where possible.
* Remove unused ports, packages, endpoints, feature flags, sample files, and default accounts.

### Agent checklist

* Does this change introduce a debug feature, permissive setting, or default credential?
* Is CORS restricted to known Angular origins?
* Are reverse-proxy headers and trusted proxy configuration understood?
* Are errors safe for clients and useful for operators?
* Are security settings repeatable through configuration or infrastructure-as-code?

---

## A03: Software Supply Chain Failures

### Risk

A vulnerable, malicious, abandoned, or tampered dependency, build tool, CI action, container image, extension, or package registry artifact compromises the application.

### Mandatory controls

* Track direct and transitive dependencies.
* Commit and review `go.sum` and the frontend lockfile.
* Prefer exact or intentionally controlled dependency versions.
* Use trusted registries and official project sources.
* Do not download packages from random websites or copy vendor code without review.
* Generate and retain an SBOM for release builds.
* Scan Go dependencies with `govulncheck`.
* Run `npm audit` for frontend dependency visibility.
* Review dependency additions as security-relevant changes.
* Update critical vulnerabilities on a risk-based timeline.
* Protect source control, package registries, CI/CD systems, and artifact repositories with MFA and least privilege.
* Require review before code can be promoted to production.
* Promote verified build artifacts across environments rather than rebuilding different artifacts per environment.
* Use protected branches and required checks for pull requests.
* Pin GitHub Actions and other CI actions to vetted versions or commit SHAs.
* Keep the `GITHUB_TOKEN` and other CI secrets scoped to the minimum permissions needed by each job.
* Split CI into separate lint, test, build, scan, and deploy jobs so privileged steps stay isolated.
* Prefer OIDC federation to cloud providers instead of long-lived deployment keys when the platform supports it.
* Use protected environments with approval gates for deploy jobs.
* Treat CI logs as sensitive and do not echo secrets, tokens, request bodies, or package credentials.

### Agent rules

Before adding or updating a dependency, ask permission and provide:

* Package name and version
* Official source
* Why existing code or dependencies cannot solve the need
* Known maintenance/security posture
* Expected lockfile changes
* Tests needed after the change

Never run:

```bash
go get -u ./...
go mod tidy
npm install
npm update
npm audit fix
npm audit fix --force
```

without permission.

---

## A04: Cryptographic Failures

### Risk

Sensitive data is exposed because encryption, key management, randomness, password storage, TLS, cookies, or cryptographic algorithms are weak or incorrectly implemented.

### Mandatory controls

* Require HTTPS in production.
* Use modern TLS through managed infrastructure or Go’s maintained standard library defaults.
* Redirect HTTP to HTTPS where appropriate and enable HSTS after deployment is confirmed.
* Do not create custom cryptography.
* Use `crypto/rand` for security-sensitive random values.
* Use established password hashing such as Argon2id, scrypt, PBKDF2, or bcrypt with appropriate parameters.
* Never encrypt passwords reversibly.
* Keep keys and secrets in environment-specific secret management, not source code.
* Rotate secrets when exposure is suspected.
* Use secure cookies:

  * `Secure`
  * `HttpOnly`
  * appropriate `SameSite`
  * narrow `Path` and `Domain`
  * short expiration where appropriate
* Do not log credentials, raw tokens, authorization headers, reset links, or sensitive personal data.
* Encrypt sensitive data at rest when required by business, legal, or contractual needs.
* Prevent caching of sensitive responses.

### Agent checklist

* Is a secret, token, password, private key, or sensitive value being stored or transmitted?
* Is Go standard-library crypto used instead of custom algorithms?
* Are cookies secure and scoped?
* Is the data minimized and redacted in logs?
* Does this change weaken TLS, certificate validation, or encryption? If yes, stop.

---

## A05: Injection

### Risk

Untrusted input is interpreted as code or commands by a database, browser, shell, ORM, template engine, file system, or external service.

### Go/GORM rules

Use parameterized values:

```go
db.Where("email = ?", email).First(&user)
```

Never build conditions with concatenation or formatting:

```go
// Forbidden
db.Where(fmt.Sprintf("email = '%s'", email)).First(&user)
```

Do not pass user input directly into:

* `Raw`
* `Exec`
* `Select`
* `Order`
* `Group`
* `Having`
* `Joins`
* table names
* column names
* SQL fragments
* sort expressions

Values can be parameterized. SQL identifiers generally cannot. Use server-side allowlists for sort columns, directions, report fields, and filters.

### Angular rules

* Use Angular template binding and interpolation instead of manual DOM manipulation.
* Do not use `innerHTML`, `ElementRef.nativeElement`, or DOM APIs with untrusted input unless explicitly reviewed.
* Do not use `DomSanitizer.bypassSecurityTrust...` without a documented security review.
* Treat all external HTML, Markdown, URLs, attachment names, error messages, and vulnerability descriptions as untrusted.
* Validate and allowlist URLs before rendering external links.

### General rules

* Validate input on the server with positive allowlists, type checks, length limits, range limits, and format constraints.
* Use request DTOs with explicit allowed fields.
* Reject unexpected fields for sensitive write requests where practical.
* Avoid shelling out. If a command is unavoidable, use fixed command paths, fixed arguments, allowlists, context timeouts, and no shell interpreter.
* Never use user-controlled URLs without SSRF protections.
* Fuzz parsers, filters, search, and import functionality.

---

## A06: Insecure Design

### Risk

Required security controls were never designed. Perfect code cannot fix a workflow or architecture that permits unsafe outcomes.

### Mandatory design practices

Before implementing a feature involving authentication, tenant data, workflow changes, uploads, integrations, exports, sensitive data, or AI:

1. Identify assets that need protection.
2. Identify actors and roles.
3. Identify trust boundaries.
4. Define happy-path and failure-path behavior.
5. Define abuse cases.
6. Define authorization rules.
7. Define audit requirements.
8. Define rate limits, retry behavior, and recovery behavior.
9. Define what happens when external systems fail.
10. Add security acceptance criteria and negative tests.

### Required abuse cases for this application

* A user tries to access another organization’s assets.
* A user attempts to bypass remediation approval.
* A workflow status is changed out of order.
* A user uploads a malicious or oversized file.
* A user manipulates a CVE ID, asset ID, or work-order ID.
* An external vulnerability API returns malformed, unexpected, stale, or malicious content.
* An attacker causes excessive NIST/NVD API calls.
* A chatbot attempts to reveal another tenant’s data or perform privileged actions.
* A user attempts to export more data than their role allows.

### Workflow security rule

Workflow state transitions must be enforced in backend domain logic.

Example:

```text
Open -> Assigned -> In Remediation -> Patch Applied -> Verified -> Closed
```

The API must reject invalid transitions. High-risk actions such as risk acceptance, exception approval, closure, reopening, export, or deletion require explicit permission checks and audit events.

---

## A07: Authentication Failures

### Risk

Attackers gain access through weak passwords, stolen credentials, weak recovery flows, insecure sessions, token mistakes, session fixation, missing MFA, or lack of brute-force protections.

### Mandatory controls

* Prefer an established identity provider using OAuth 2.0/OpenID Connect for production authentication.
* Require MFA for administrators and high-risk roles.
* Use rate limiting and progressive delays for login, password reset, and token-refresh endpoints.
* Avoid user enumeration: use generic messages such as “Invalid username or password.”
* Store passwords only with strong adaptive password hashing.
* Use short-lived access tokens.
* Use server-side refresh-token sessions when refresh tokens are implemented.
* Validate JWT issuer, audience, expiration, signature, scopes, and intended use.
* Do not accept tokens with unexpected algorithms or unsigned tokens.
* Rotate or invalidate sessions after logout, password reset, privilege change, suspicious activity, and account disablement.
* Regenerate session IDs on login.
* Store browser sessions in secure, HttpOnly cookies where possible.
* Do not place authentication tokens in URLs.
* Do not store long-lived tokens in local storage.
* Use secure password reset tokens with expiration, one-time use, and rate limiting.

### Agent checklist

* Is authentication delegated to a hardened identity provider where possible?
* Does the server validate tokens completely?
* Are session cookies secure?
* Are failed logins rate limited and audited?
* Can a password-reset or registration endpoint reveal whether an account exists?

---

## A08: Software or Data Integrity Failures

### Risk

The application treats untrusted code, builds, packages, webhooks, serialized data, updates, or artifacts as trusted without verifying integrity.

### Mandatory controls

* Require code review for application, infrastructure, and CI/CD changes.
* Use protected branches and required checks.
* Use verified CI/CD actions and pinned versions where feasible.
* Restrict CI/CD secrets by environment and job.
* Do not deserialize untrusted data into unsafe object structures.
* Prefer typed JSON DTOs with strict validation.
* Verify signatures for webhooks and external callbacks.
* Verify integrity and provenance of release artifacts.
* Use trusted package registries only.
* Do not load remote scripts, plugins, or browser code from untrusted sources.
* Do not use external CDN assets unless approved, integrity-protected, and compatible with CSP.
* Do not trust data merely because it came from a “known” URL; validate schema, type, size, and expected fields.

### Application-specific auth integrity rule

The auth flow must not rely solely on client-held JWTs for session validity.

* Access tokens are verified for signature, issuer, audience, scope, token use, and expiry.
* The server must also confirm that the paired session ID is still active.
* Refresh tokens are the only credential that can renew the session.
* Refresh token rotation must not leave the old session active.

### External API rule

For NIST/NVD-style integrations:

* Use a fixed, configured allowlist of approved API hosts.
* Never accept an arbitrary URL from the browser and fetch it server-side.
* Set connection, read, and total request timeouts.
* Restrict redirects.
* Limit response size.
* Validate response structure before persistence.
* Cache safely and rate-limit outbound requests.
* Treat external data as untrusted until validated.
* Log integration failures without logging secrets or entire sensitive payloads.

---

## A09: Security Logging and Alerting Failures

### Risk

The application cannot detect, investigate, or respond to attacks because important events are absent, unsafe, unactionable, unprotected, or ignored.

### Mandatory audit events

Log security-relevant events with structured fields:

* Login success and failure
* Logout
* MFA enrollment and failure
* Password reset request and completion
* Access denied
* Privilege or role changes
* Organization membership changes
* Sensitive export attempts
* Create/update/delete actions for assets, vulnerabilities, work orders, and exceptions
* Workflow approvals and state transitions
* Integration configuration changes
* API key or secret rotation
* Rate-limit events
* Validation failures that indicate suspicious behavior
* Admin actions
* Unexpected application errors

Recommended fields:

```text
timestamp
request_id
actor_id
organization_id
action
resource_type
resource_id
result
ip_address_or_privacy_safe_equivalent
user_agent_summary
error_code
```

### Logging rules

* Never log passwords, tokens, authorization headers, cookies, API keys, private keys, raw sensitive payloads, or full stack traces to users.
* Sanitize untrusted input before logging to prevent log injection.
* Use structured logs.
* Protect log storage from unauthorized modification or deletion.
* Retain logs according to operational and legal requirements.
* Create actionable alerts for repeated authentication failures, authorization failures, anomalous exports, secret-related events, and elevated-error spikes.
* Maintain response playbooks for critical alerts.

---

## A10: Mishandling of Exceptional Conditions

### Risk

Unexpected conditions cause crashes, information leaks, partial writes, unauthorized access, unsafe defaults, race conditions, resource exhaustion, or fail-open behavior.

### Mandatory controls

* Fail closed on authorization, validation, integrity, and dependency failures.
* Handle errors where they occur; do not rely only on a top-level handler.
* Use Gin recovery middleware, but do not expose panic details to clients.
* Return stable error codes and safe error messages.
* Use request-scoped database transactions for HTTP request writes.
* Roll back request transactions on failure.
* Set context deadlines and cancellation for database and external API calls.
* Limit request-body size, upload size, pagination size, filter complexity, and query duration.
* Handle missing, null, malformed, duplicate, stale, and out-of-order data safely.
* Do not partially complete sensitive workflow actions.
* Use idempotency protections for operations that could be retried.
* Test timeouts, unavailable dependencies, database errors, duplicate requests, malformed bodies, and authorization failures.
* Run race detection in Go tests when appropriate.

### Error response pattern

Clients should receive safe responses such as:

```json
{
  "code": "VALIDATION_ERROR",
  "message": "The request could not be processed.",
  "requestId": "..."
}
```

Detailed error causes belong in protected structured logs, not in browser responses.

---

# 4. Go, Gin, and GORM Security Practices

## 4.1 Go

* Keep Go current with supported releases.
* Use `context.Context` for request-scoped work, deadlines, cancellation, database calls, and external calls.
* Use `crypto/rand` for security-sensitive randomness.
* Prefer Go standard-library security primitives.
* Do not write custom authentication, crypto, serialization, or parsing code unless necessary and reviewed.
* Run:

  * `go test ./...`
  * `go vet ./...`
  * `go test -race ./...`
  * `govulncheck ./...`
* Add fuzz tests for parsers, query filters, import code, external API responses, and any complex input handling.
* Use explicit HTTP server timeouts in production.
* Return wrapped errors internally but map them to safe API errors externally.

## 4.2 Gin

* Use route groups with authentication and authorization middleware.
* Use `ShouldBindJSON` or equivalent binding methods with explicit validation.
* Add validation tags for required fields, length, format, ranges, enum values, and identifiers.
* Create custom validators for business-specific rules.
* Apply request-size limits before parsing bodies or uploads.
* Use custom recovery and logging middleware that redacts secrets.
* Configure CORS explicitly with known origins only.
* Do not use permissive CORS defaults in production.
* Configure trusted proxies intentionally.
* Do not use client IP forwarding headers unless proxy trust is configured correctly.
* Use rate limiting for authentication, password reset, expensive search, export, external lookup, and chatbot endpoints.
* Avoid exposing stack traces, Gin debug output, route lists, or internal error values.

## 4.3 GORM and database access

* Use parameterized queries for values.
* Keep table names, column names, sort fields, joins, and SQL fragments server-controlled or strictly allowlisted.
* Prefer typed methods and explicit query construction.
* Use request DTOs rather than binding browser payloads directly into GORM models.
* Explicitly select fields that can be updated.
* Protect against mass assignment:

  * Do not bind untrusted JSON directly into a model containing roles, tenant IDs, ownership fields, approval flags, or workflow states.
  * Map allowed DTO fields into domain models intentionally.
* Scope all tenant-owned queries by organization, and only fall back to user-owned scope for legacy code that has not yet been migrated.
* Use the request-scoped transaction from context for request-owned repository work.
* Use nested GORM transactions only when savepoint behavior or focused multi-step persistence is intentional.
* Prefer soft deletes for security-sensitive or audit-relevant records.
* Do not use `Unscoped()` unless the caller is an explicit retention, recovery, cleanup, or test path.
* Use a least-privileged database account for the running application.
* Use a separate migration account where practical.
* Do not run automatic schema changes against production without approval.
* Do not expose database errors directly to API clients.
* Use database constraints for important invariants, but do not rely on them as the only authorization control.

---

# 5. Angular and TypeScript Security Practices

## 5.1 Angular and Angular SSR

* Keep Angular and Angular CLI current.
* Use Angular template interpolation and binding.
* Avoid direct DOM manipulation.
* Treat all values inserted into the DOM as untrusted unless proven otherwise.
* Do not use `bypassSecurityTrustHtml`, `bypassSecurityTrustScript`, `bypassSecurityTrustStyle`, `bypassSecurityTrustUrl`, or `bypassSecurityTrustResourceUrl` without explicit approval and a documented threat analysis.
* Do not render untrusted HTML directly.
* Sanitize Markdown or rich text through an approved server-side or client-side sanitizer before rendering.
* Enforce a Content Security Policy in production.
* Consider Trusted Types as an additional defense against DOM XSS.
* Do not rely on Angular route guards for authorization; they are navigation controls, not a security boundary.
* Keep browser error messages generic and do not display raw backend errors.
* Disable production source maps publicly unless there is a justified secure-access process.
* Avoid third-party scripts. Each one requires approval and privacy/security review.
* Treat the Node/Express SSR layer as server-side code: do not put secrets into rendered HTML, transfer state, logs, or browser bundles.
* Validate and sanitize any data rendered during SSR the same way browser-rendered data is treated.

## 5.2 TypeScript

Use strict compiler configuration.

Recommended settings include:

```json
{
  "compilerOptions": {
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "noUncheckedIndexedAccess": true,
    "useUnknownInCatchVariables": true,
    "noImplicitOverride": true,
    "noFallthroughCasesInSwitch": true,
    "forceConsistentCasingInFileNames": true
  }
}
```

Rules:

* Avoid `any`; use explicit types, `unknown`, type guards, and validated DTOs.
* Validate API responses before treating them as trusted application data.
* Do not trust types as runtime validation.
* Model roles, workflow states, and permissions as restricted unions or enums.
* Keep environment configuration free of secrets; frontend environment files are public after bundling.
* Do not place API keys or privileged third-party credentials in Angular configuration.

## 5.3 Browser authentication and CSRF

For cookie-based authentication:

* Use `Secure`, `HttpOnly`, and appropriate `SameSite` cookies.
* Implement CSRF protection for state-changing requests.
* Validate `Origin` or `Referer` where appropriate.
* Keep CORS restrictive.
* Ensure state-changing methods require anti-CSRF protections.

For bearer-token flows:

* Keep token lifetime short.
* Avoid local storage for long-lived secrets.
* Validate tokens server-side on every request.
* Never assume a token being present means the user is authorized for the requested resource.

For browser login forms:

* Use standard HTML form controls and appropriate `autocomplete` values for usernames and passwords.
* Keep validation client-side for usability only; enforce all real checks on the server.
* Do not persist credentials, tokens, or session identifiers in browser storage, URLs, or form state after submission.
* Keep login failures generic so the browser does not reveal whether a username or password was wrong.

---

# 6. API Security Requirements

The application API must also address OWASP API Security concerns.

## Mandatory controls

* Authenticate every non-public endpoint.
* Authorize every object access.
* Prevent mass assignment with request DTOs.
* Limit response fields by role and use case.
* Enforce pagination limits.
* Allowlist filter, search, and sort fields.
* Apply rate limits to sensitive and expensive operations.
* Limit request body sizes.
* Validate content types.
* Use API versioning deliberately.
* Use opaque or non-sequential identifiers where enumeration risk is high, but never treat obscurity as authorization.
* Add idempotency for high-value creation or workflow operations.
* Protect privileged `/internal` routes with certificate authentication and route-level service identity authorization.
* Secure file uploads:

  * allowlist type and extension
  * validate actual content where possible
  * size limits
  * malware scanning where applicable
  * generate server-side filenames
  * store outside web root
  * do not trust client MIME type
* Audit exports and sensitive bulk operations.

---

# 7. Future AI/Chatbot Security Rules

When chatbot functionality is added:

* Treat user prompts, retrieved documents, external tool results, and model outputs as untrusted.
* Do not let the model bypass authorization, tenant isolation, approval workflows, or server-side policy checks.
* Retrieve only records the authenticated user is authorized to access.
* Scope every retrieval query by tenant and permission.
* Do not send secrets, full audit logs, access tokens, credentials, or sensitive tenant data to an external AI provider such as OpenAI without explicit approval.
* Require server-side policy checks before an AI-driven action creates, updates, closes, suppresses, or approves a workflow item.
* Present AI actions as proposals requiring user confirmation.
* Log AI tool requests and outcomes without logging sensitive prompt content unnecessarily.
* Defend against prompt injection by treating all retrieved and user-provided text as data, not instructions.
* Restrict AI tools to small, purpose-built operations with explicit input validation and authorization.

## 7.1 Locked prompt policy

For any backend AI feature that ranks, summarizes, or extracts data:

* Keep the instruction block in backend code, not in the frontend, not in the request body, and not in configuration that a user can change.
* Use one hardcoded system prompt per use case, version it with the code, and test it like application logic.
* Put user content, retrieved records, and candidate lists in a separate user/data message.
* Tell the model explicitly that user text is untrusted data and that embedded instructions must be ignored.
* Require JSON-only output with a fixed schema.
* Reject responses that do not match the schema or that include prose, markdown, or code fences.
* Cap prompt size, candidate count, and response size before sending anything to the model.
* Prefer read-only AI behavior first; any write action needs explicit server-side confirmation and authorization.
* Treat model output as advisory until backend validation accepts it.
* Add regression tests for prompt-injection text, oversized inputs, malformed outputs, and candidate spoofing.

---

# 8. Required Testing and Release Checks

## Required security tests

Every new protected endpoint should include tests for:

* unauthenticated access
* wrong role
* wrong tenant
* correct tenant and role
* malformed request body
* unknown or extra fields where applicable
* invalid workflow transition
* rate-limit behavior where relevant
* safe error response
* audit-event creation for sensitive actions

## Approved security verification

Run these only after permission if they download tools, alter dependencies, or use network access:

```bash
go test ./...
go vet ./...
go test -race ./...
govulncheck ./...
npm ci
npm run lint
npm test
npm audit
```

Do not automatically apply remediation commands that alter dependencies. Review findings first.

## Release checklist

Before deployment:

* [ ] No secrets in source control or build output
* [ ] Dependencies scanned and reviewed
* [ ] Go and frontend tests pass
* [ ] Authorization tests include cross-tenant negatives
* [ ] CORS is restricted
* [ ] Production debug features are disabled
* [ ] Security headers are enabled and tested
* [ ] TLS is enforced
* [ ] Internal service certificates are verified and route-scoped before privileged `/internal` work is allowed
* [ ] Request-scoped transaction commit and rollback behavior is tested
* [ ] Destructive delete paths are audited, and soft-delete paths cannot expose deleted records to normal users
* [ ] Database credentials are least privilege
* [ ] Logs are structured, redacted, retained, and monitored
* [ ] Error responses are safe
* [ ] External integrations are allowlisted and time-limited
* [ ] Sensitive workflow actions are audited
* [ ] Deployment and rollback plans are documented

---

# 9. Incident Response Expectations

When a suspected security issue is found:

1. Stop unsafe work.
2. Do not exploit beyond the minimum safe confirmation.
3. Preserve evidence safely.
4. Do not paste secrets or sensitive records into chat, tickets, commits, or logs.
5. Report:

   * affected component
   * severity
   * exploitability
   * affected tenants/data
   * proof or safe reproduction
   * immediate containment
   * remediation
   * validation
   * whether credentials or tokens need rotation
6. Add regression tests after remediation.
7. Review similar code paths for the same vulnerability pattern.

---

# 10. Authoritative References

## OWASP

* [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
* [OWASP Application Security Verification Standard 5.0](https://owasp.org/www-project-application-security-verification-standard/)
* [OWASP API Security Project](https://owasp.org/www-project-api-security/)
* [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
* [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
* [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
* [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
* [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
* [OWASP Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

## Go

* [Go Security](https://go.dev/doc/security/)
* [Go Security Best Practices](https://go.dev/doc/security/best-practices)
* [Go Vulnerability Management and govulncheck](https://go.dev/security/vuln/)
* [Go Fuzzing](https://go.dev/doc/security/fuzz/)

## Gin

* [Gin Documentation](https://gin-gonic.com/en/docs/)
* [Gin Model Binding and Validation](https://gin-gonic.com/en/docs/binding/binding-and-validation/)
* [Gin Custom Validators](https://gin-gonic.com/en/docs/binding/custom-validators/)
* [Gin FAQ: CORS, Authentication, Logging, Production](https://gin-gonic.com/en/docs/faq/)

## GORM

* [GORM Security Guidance](https://gorm.io/docs/security.html)
* [GORM Documentation](https://gorm.io/docs/)

## Angular and TypeScript

* [Angular Security Best Practices](https://angular.dev/best-practices/security)
* [Angular Security Guide](https://angular.dev/best-practices/security)
* [TypeScript TSConfig Reference](https://www.typescriptlang.org/tsconfig/)
* [TypeScript tsconfig.json Documentation](https://www.typescriptlang.org/docs/handbook/tsconfig-json.html)

## npm

* [npm Dependency Security Audits](https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities/)
* [npm Threats and Mitigations](https://docs.npmjs.com/threats-and-mitigations/)
* [npm Trusted Publishing](https://docs.npmjs.com/trusted-publishers/)

## Docker and PostgreSQL

* [PostgreSQL Security](https://www.postgresql.org/docs/current/security.html)
* [Docker Compose Documentation](https://docs.docker.com/compose/)

---

## Document Maintenance

Review this file:

* At least quarterly
* After an authentication or authorization change
* Before introducing a new external integration
* Before adding file uploads, exports, payment-like actions, or AI tools
* After a security incident
* After major Go, Gin, GORM, Angular, TypeScript, npm, database, cloud, or CI/CD changes
* When OWASP releases a new Top 10 or ASVS version
