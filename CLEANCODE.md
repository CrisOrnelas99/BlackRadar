## Purpose

This document defines clean-code, architecture, maintainability, and testing standards for this application.

**Stack**

* Backend: Go, Gin, GORM, PostgreSQL, pgx, bcrypt, JWT
* Frontend: Angular, Angular SSR, TypeScript, Node/Express, RxJS, Vitest

This is mandatory guidance for developers and coding agents when building, maintaining, debugging, or refactoring the application.

Security requirements belong in `SECURITY.md`. This document focuses on producing code that is understandable, testable, decoupled, consistent, and safe to change.

---

# 1. Core Principles

Every change must optimize for these outcomes:

1. **Correctness first**
2. **Readability second**
3. **Simple design over clever design**
4. **Small, focused responsibilities**
5. **Explicit dependencies and data flow**
6. **Easy testing and safe refactoring**
7. **Consistent conventions across the codebase**
8. **Minimal unintended changes**

Prefer boring, obvious code.

Avoid clever abstractions, magic behavior, overly generic helpers, deep inheritance, hidden side effects, and premature optimization.

A future developer should be able to understand the purpose of a file, function, API endpoint, query, or component without tracing through unrelated code.

---

# 2. Coding-Agent Rules

## 2.1 Before making changes

Before editing code, the coding agent must:

1. Read `SECURITY.md` and this file.
2. Inspect the affected feature, tests, routes, services, repositories, models, DTOs, migrations, and frontend components.
3. Identify the smallest safe change.
4. Follow existing project conventions when they are reasonable.
5. Reuse existing utilities before introducing new abstractions.
6. Add or update tests when behavior changes.
7. Explain any deviation from this document.

Do not refactor unrelated files while fixing a focused bug.

Do not rename, reformat, or reorganize large areas of code unless explicitly requested.

## 2.2 Ask before expanding scope

Ask for approval before:

* Adding a third-party dependency.
* Updating or removing dependencies.
* Changing package versions, lockfiles, `go.mod`, or `go.sum`.
* Adding code generation tools.
* Creating or changing database migrations.
* Replacing a core architecture pattern.
* Performing a large-scale refactor.
* Changing authentication, authorization, JWT, password hashing, SSR behavior, infrastructure, CI/CD, or deployment configuration.
* Running a command that downloads packages, modifies dependencies, modifies data, or contacts external systems.

Read `SECURITY.md` for the full approval and safety policy.

## 2.3 Do not create unnecessary abstraction

Do not create an interface, helper, factory, manager, wrapper, base class, or utility merely because it might be useful later.

Create an abstraction only when at least one is true:

* There are two or more real implementations.
* The dependency must be replaced in tests.
* The abstraction expresses a meaningful domain boundary.
* It removes duplicated business logic.
* It simplifies a difficult dependency.

Avoid names such as:

```text
Helper
Manager
Processor
HandlerUtil
Common
Misc
DataService
GeneralService
Utils
```

Use names that describe the business responsibility.

Good examples:

```text
VulnerabilityService
AssetRepository
JWTVerifier
PasswordHasher
WorkOrderTransitionService
NVDClient
OrganizationMembershipRepository
```

---

# 3. Function Design Rules

## 3.1 One function, one responsibility

A function should do one meaningful job.

Bad:

```go
func CreateAsset(c *gin.Context) {
    // Parse JSON
    // Validate request
    // Check organization
    // Check authorization
    // Create database record
    // Call external API
    // Write audit event
    // Return JSON
}
```

Better separation:

```go
func (h *AssetHandler) Create(c *gin.Context) {
    request, err := bindCreateAssetRequest(c)
    if err != nil {
        writeError(c, err)
        return
    }

    asset, err := h.assetService.Create(c.Request.Context(), request)
    if err != nil {
        writeError(c, err)
        return
    }

    c.JSON(http.StatusCreated, toAssetResponse(asset))
}
```

Responsibilities:

```text
controller -> service -> repository -> database
```

Keep package responsibilities separate:

- `controller`: HTTP binding, route parameters, request body parsing, and response writing.
- `dto`: request and response structs.
- `service`: business validation, ownership checks, and use-case orchestration.
- `repository`: GORM/database reads and writes only.
- `model`: persistence/domain structs.
- `middleware`: Gin middleware.
- `security`: JWT and security-specific helpers.
- `config`: environment-backed configuration.
- `utils`: database helpers and database error translation.

## Go Naming

- Package names use lowercase singular words where practical: `controller`, `service`, `repository`, `middleware`.
- Exported Go names use PascalCase: `AssetController`, `NewAssetService`, `JWTManager`.
- Unexported Go names use camelCase: `assetServiceImpl`, `validateAsset`, `parseID`.
- Keep common initialisms consistently capitalized: `ID`, `URL`, `JWT`, `CVE`, `IP`, `JSON`, `DTO`.
- Constructor names should follow `NewTypeName`: `NewAssetController`, `NewJWTManager`.
- Interface names should describe behavior needed by the consuming layer.
- Avoid single-letter names except for short receivers and tight loops.
- Receiver names should be short but meaningful: `c` for controllers, `s` for services, `r` for repositories.

## Go Files

- Name files after the main concept they contain: `asset_controller.go`, `asset_service.go`, `asset_repository.go`.
- Keep tests beside the package they test with `_test.go`.
- Keep package helpers in normal implementation files, not in `errors.go`.
- Do not move DTOs into controllers.
- Do not move GORM models into DTO files.

## Go Functions

- Keep controllers thin. They should parse input, call services, and write responses.
- Keep service methods free of Gin response-writing logic.
- Keep repositories free of HTTP concerns.
- Prefer early returns for validation and error paths.
- Keep validation close to the layer that owns the rule.
- Use `context.Context` through request-owned context where database or request-scoped work is involved.
- Avoid building SQL with string concatenation or `fmt.Sprintf`.
- Use parameterized GORM calls for values.

## Error Files

Keep the existing error style.

Package `errors.go` files should contain only:

```go
func CloseWorkOrder(workOrder WorkOrder, actor User) error {
    if workOrder.Status != WorkOrderStatusVerified {
        return ErrWorkOrderNotVerified
    }

    if actor.Role != RoleSecurityManager {
        return ErrInsufficientPermission
    }

    if workOrder.RemediationPlanID == "" {
        return ErrMissingRemediationPlan
    }

    workOrder.Status = WorkOrderStatusClosed
    return nil
}
```

Do not use `else` after a branch that already returns.

Bad:

```go
if err != nil {
    return err
} else {
    return process(result)
}
```

Better:

```go
if err != nil {
    return err
}

return process(result)
```

## 3.4 Avoid boolean flag parameters

Boolean parameters hide intent.

Bad:

```go
func GetAssets(includeInactive bool) ([]Asset, error)
```

Better:

```go
func ListActiveAssets() ([]Asset, error)
func ListAssets(filter AssetFilter) ([]Asset, error)
```

Or:

```go
type AssetFilter struct {
    IncludeInactive bool
    Status          AssetStatus
    OrganizationID  string
}
```

## 3.5 Limit parameter complexity

Prefer a small number of meaningful parameters.

Use a request or options struct when a function requires several related values.

Bad:

```go
func CreateWorkOrder(
    orgID string,
    assetID string,
    vulnerabilityID string,
    title string,
    description string,
    priority string,
    dueDate time.Time,
    assignedTo string,
) error
```

Better:

```go
type CreateWorkOrderInput struct {
    OrganizationID   string
    AssetID          string
    VulnerabilityID  string
    Title            string
    Description      string
    Priority         WorkOrderPriority
    DueDate          *time.Time
    AssignedUserID   *string
}
```

## 3.6 Keep side effects visible

Functions that write to the database, call external APIs, publish events, send notifications, mutate state, or write files should make that behavior clear through naming and placement.

Good names:

```text
CreateAsset
UpdateVulnerabilityStatus
AssignWorkOrder
PublishAuditEvent
FetchCVEFromNVD
SendRemediationNotification
```

Avoid misleading names:

```text
Process
Handle
DoThing
Run
Execute
UpdateData
```

---

# 4. Naming Conventions

## 4.1 General naming rules

Names must communicate purpose.

Use domain terms consistently:

```text
Organization
Asset
Vulnerability
CVE
CWE
WorkOrder
RemediationPlan
RiskAcceptance
Exception
AuditEvent
Tenant
Membership
```

Do not use multiple terms for the same thing.

Bad:

```text
Company
Business
Client
Tenant
Organization
```

Choose one canonical term, such as `Organization`, and use it consistently.

## 4.2 Avoid vague names

Avoid:

```text
data
info
item
obj
thing
result
response
service
manager
helper
util
temp
value
payload
record
```

These names are acceptable only when their meaning is already obvious in a very small scope.

Bad:

```go
func Process(data []byte) error
```

Better:

```go
func ParseNVDResponse(body []byte) (NVDResponse, error)
```

Bad:

```ts
const result = await service.getData();
```

Better:

```ts
const vulnerabilities = await vulnerabilityApi.listOpenVulnerabilities();
```

## 4.3 Go naming

Use Go conventions:

```text
Exported names: PascalCase
Unexported names: camelCase
Packages: lowercase, short, descriptive, no underscores
Constants: PascalCase or camelCase, depending on visibility
```

Use standard acronym casing:

```go
userID
organizationID
assetID
requestID
apiClient
httpClient
jwtVerifier
CVE
CWE
NVD
URL
HTTP
JSON
JWT
```

Good:

```go
type AssetRepository interface {}
type JWTVerifier interface {}
func ParseCVEID(value string) (string, error) {}
```

Avoid package stuttering:

```go
// Bad
asset.AssetService
vulnerability.VulnerabilityRepository

// Better
asset.Service
vulnerability.Repository
```

## 4.4 TypeScript naming

Use:

```text
Classes, interfaces, types, enums: PascalCase
Functions, variables, methods: camelCase
Constants: camelCase or UPPER_SNAKE_CASE for true immutable globals
Files: kebab-case
Observable streams: suffix with $
```

Examples:

```ts
export interface AssetResponse {}
export type WorkOrderStatus = 'open' | 'assigned' | 'closed';

const activeVulnerabilities$ = this.vulnerabilityStore.activeVulnerabilities$;

function buildAssetFilter(): AssetFilter {}
```

Use meaningful boolean names:

```ts
isLoading
isSaving
hasPermission
canCloseWorkOrder
shouldRetry
```

Avoid:

```ts
loading
flag
status
check
enabled
value
```

unless the context is extremely clear.

## 4.5 Database naming

Use PostgreSQL naming consistently:

```text
Tables: plural snake_case
Columns: snake_case
Foreign keys: <entity>_id
Timestamps: created_at, updated_at, deleted_at
Boolean columns: is_, has_, can_
Join tables: organization_users, asset_vulnerabilities
```

Examples:

```text
organizations
assets
vulnerabilities
work_orders
remediation_plans
organization_id
assigned_user_id
created_at
is_active
```

---

# 5. Comments and Documentation

## 5.1 Comments explain why, not what

Good comments explain:

* Why a decision exists
* Business rules
* Security requirements
* Non-obvious edge cases
* External API limitations
* Performance tradeoffs
* Temporary workarounds
* Important invariants

Bad:

```go
// Set the status to closed.
workOrder.Status = WorkOrderStatusClosed
```

Better:

```go
// Closure is allowed only after verification so unresolved remediation
// work cannot be marked complete through the API.
workOrder.Status = WorkOrderStatusClosed
```

## 5.2 Do not comment obvious code

Bad:

```ts
// Loop through vulnerabilities.
for (const vulnerability of vulnerabilities) {
  ...
}
```

Bad:

```go
// Return an error.
return err
```

Use clearer code instead of comments whenever possible.

## 5.3 Document exported Go types and functions

Exported Go functions, types, interfaces, constants, and variables should have doc comments.

```go
// AssetService coordinates asset lifecycle operations for an organization.
type AssetService struct {
    repository AssetRepository
}

// Create creates an asset after validating organization membership and business rules.
func (s *AssetService) Create(ctx context.Context, input CreateAssetInput) (Asset, error) {
    ...
}
```

## 5.4 TODO comments must be actionable

Do not leave vague TODO comments.

Bad:

```go
// TODO: fix later
```

Better:

```go
// TODO(#482): Replace this temporary NVD retry behavior once the integration
// supports server-provided retry headers.
```

A TODO should include:

* The required future action
* Why it is needed
* A ticket, issue, owner, or removal condition when possible

Do not leave commented-out code in the repository.

Delete it. Git history preserves old code.

---

# 6. Backend Architecture

## 6.1 Use feature-first organization

Organize code around business features, not only technical layers.

Preferred structure:

```text
cmd/
  api/
    main.go

internal/
  platform/
    config/
    database/
    auth/
    logging/
    http/
    observability/

  asset/
    handler.go
    request.go
    response.go
    service.go
    repository.go
    model.go
    errors.go
    service_test.go
    repository_test.go

  vulnerability/
    handler.go
    request.go
    response.go
    service.go
    repository.go
    model.go
    errors.go

  workorder/
    handler.go
    service.go
    repository.go
    workflow.go
    model.go

  organization/
    handler.go
    service.go
    repository.go
    membership.go
```

Do not create a giant global folder such as:

```text
controllers/
services/
repositories/
models/
utils/
helpers/
```

when those folders collect unrelated business features.

## 6.2 Dependency direction

Dependencies should move inward toward business logic.

```text
HTTP / Gin Handler
        ↓
Application Service
        ↓
Repository / External Client
        ↓
Database / External API
```

Rules:

* Handlers may depend on services.
* Services may depend on repositories and clients.
* Repositories may depend on GORM, pgx, or PostgreSQL.
* Domain/business logic must not depend on Gin.
* Repositories must not return Gin responses.
* Services must not know HTTP status codes.
* Frontend DTOs must not become database models automatically.

## 6.3 Handler responsibilities

Gin handlers should only:

* Bind and validate HTTP requests
* Read request context
* Read authenticated user and organization context
* Call a service
* Map service errors to HTTP responses
* Return response DTOs

Handlers must not contain:

* Business workflow rules
* Complex authorization logic
* Database queries
* GORM calls
* Complex mapping logic
* External API calls
* Password hashing
* JWT signing or validation logic

## 6.4 Service responsibilities

Services own application and business behavior.

Examples:

```text
CreateAsset
AssignWorkOrder
VerifyRemediation
CloseWorkOrder
AcceptRisk
SuppressVulnerability
RefreshCVEData
InviteOrganizationUser
```

Services should:

* Enforce business rules
* Enforce workflow transitions
* Coordinate repository calls
* Rely on request-scoped transaction middleware for normal HTTP request atomicity
* Call external clients
* Write audit events
* Return domain errors

Services should not:

* Depend on Gin
* Write HTTP JSON
* Parse raw request bodies
* Depend directly on browser-specific concepts

## 6.5 Repository responsibilities

Repositories own persistence behavior.

Repositories should:

* Query PostgreSQL
* Persist records
* Apply tenant scope
* Return persistence/domain data
* Use the request-scoped `GinContext` database handle when present
* Use focused nested GORM transactions only when savepoint behavior is intentional

Repositories should not:

* Decide business workflows
* Determine HTTP status codes
* Parse requests
* Call external APIs
* Create JWTs
* Hash passwords
* Make authorization decisions

## 6.6 Interfaces belong to the consumer

Declare interfaces where they are consumed.

```go
type AssetRepository interface {
    Create(ctx context.Context, asset Asset) (Asset, error)
    GetByID(ctx context.Context, organizationID, assetID string) (Asset, error)
    List(ctx context.Context, filter AssetFilter) ([]Asset, error)
}
```

A service depends on the interface:

```go
type AssetService struct {
    repository AssetRepository
}
```

Do not create interfaces for every struct automatically.

Use interfaces when they improve testing, isolate a real boundary, or allow multiple implementations.

---

# 7. Go Standards

## 7.1 Formatting and imports

All Go code must be formatted with `gofmt`.

Keep imports grouped:

```go
import (
    "context"
    "errors"
    "fmt"
    "net/http"

    "github.com/gin-gonic/gin"
    "gorm.io/gorm"

    "your-app/internal/asset"
)
```

Do not use dot imports.

Avoid blank imports unless required and documented.

## 7.2 Context usage

Use `context.Context` for request-scoped work.

Rules:

* Put `context.Context` first in function signatures.
* Pass context through service, repository, and external-client calls.
* Do not store a context in a struct.
* Do not create `context.Background()` inside request handling.
* Respect cancellation and deadlines.
* Pass the incoming request context to database and outbound calls.

Good:

```go
func (s *AssetService) GetByID(ctx context.Context, input GetAssetInput) (Asset, error) {
    return s.repository.GetByID(ctx, input.OrganizationID, input.AssetID)
}
```

## 7.3 Error handling

Errors must be explicit, meaningful, and testable.

Use sentinel errors for stable domain states:

```go
var (
    ErrAssetNotFound             = errors.New("asset not found")
    ErrWorkOrderNotVerified      = errors.New("work order is not verified")
    ErrInvalidWorkflowTransition = errors.New("invalid workflow transition")
)
```

Wrap underlying errors with context:

```go
asset, err := s.repository.GetByID(ctx, organizationID, assetID)
if err != nil {
    return Asset{}, fmt.Errorf("get asset %s: %w", assetID, err)
}
```

Check errors with `errors.Is` or `errors.As`.

```go
if errors.Is(err, ErrAssetNotFound) {
    writeNotFound(c, "asset not found")
    return
}
```

Rules:

* Error messages start lowercase.
* Error messages do not end in punctuation.
* Do not log an error repeatedly at every layer.
* Log at the application boundary where context is richest.
* Return safe errors to the client.
* Preserve useful internal error context through wrapping.
* Do not return raw database, JWT, bcrypt, or external API errors directly to API clients.

Layered Go API errors follow this repository -> service -> controller flow:

* Repositories translate GORM, PostgreSQL, and constraint errors into repository sentinel errors.
* Services translate repository sentinel errors into service sentinel errors.
* Service translation must preserve the repository cause with `fmt.Errorf("%w: %w", serviceErr, repositoryErr)`.
* Controllers check service errors with `errors.Is` and map them to HTTP status codes.
* Controllers must use the shared `HandleError` helper for safe JSON error responses.
* Controllers must not import repository packages only to classify errors.

Example:

```go
if err != nil {
    return Asset{}, fmt.Errorf("%w: %w", ErrNotFound, err)
}
```

The returned error must satisfy both `errors.Is(err, ErrNotFound)` and `errors.Is(err, repository.ErrAssetNotFound)` so the API keeps clean boundaries without losing debugging context.

## 7.4 Avoid hidden goroutines

Do not start goroutines without an owner, cancellation strategy, error handling, and shutdown plan.

Every goroutine must answer:

* Who starts it?
* Who stops it?
* How is it cancelled?
* How are errors handled?
* What happens during shutdown?
* Can it leak memory or block forever?

Do not launch background work from a request handler unless it is designed as a managed job.

## 7.5 Prefer explicit data types

Use domain types where ambiguity is harmful.

```go
type OrganizationID string
type AssetID string
type VulnerabilityID string
type WorkOrderID string
type CVEID string
```

Use typed status values:

```go
type WorkOrderStatus string

const (
    WorkOrderStatusOpen          WorkOrderStatus = "open"
    WorkOrderStatusAssigned      WorkOrderStatus = "assigned"
    WorkOrderStatusInRemediation WorkOrderStatus = "in_remediation"
    WorkOrderStatusVerified      WorkOrderStatus = "verified"
    WorkOrderStatusClosed        WorkOrderStatus = "closed"
)
```

Do not pass arbitrary strings where a domain-specific type is appropriate.

---

# 8. Gin Standards

## 8.1 Route structure

Use route groups by API version and feature.

```go
api := router.Group("/api/v1")
api.Use(authMiddleware.RequireAuthenticatedUser())

assets := api.Group("/assets")
assets.GET("", assetHandler.List)
assets.POST("", assetHandler.Create)
assets.GET("/:assetID", assetHandler.GetByID)
assets.PATCH("/:assetID", assetHandler.Update)
assets.DELETE("/:assetID", assetHandler.Delete)
```

Keep route registration centralized.

Do not hide route setup inside unrelated services.

## 8.2 Request and response DTOs

Use explicit request and response types.

Do not bind browser JSON directly into GORM models.

```go
type CreateAssetRequest struct {
    Name        string `json:"name" binding:"required,max=200"`
    AssetType   string `json:"assetType" binding:"required,max=100"`
    Description string `json:"description" binding:"max=2000"`
}
```

```go
type AssetResponse struct {
    ID          string    `json:"id"`
    Name        string    `json:"name"`
    AssetType   string    `json:"assetType"`
    Description string    `json:"description"`
    CreatedAt   time.Time `json:"createdAt"`
}
```

Use mapping functions:

```go
func toAssetResponse(asset Asset) AssetResponse {
    return AssetResponse{
        ID:          asset.ID,
        Name:        asset.Name,
        AssetType:   asset.AssetType,
        Description: asset.Description,
        CreatedAt:   asset.CreatedAt,
    }
}
```

## 8.3 Validation

Validation belongs at multiple levels:

```text
Handler validation:
- Required fields
- Type correctness
- Maximum length
- Valid JSON structure

Service validation:
- Business rules
- Workflow rules
- Cross-record rules
- Tenant and role rules

Database validation:
- Foreign keys
- Unique constraints
- Not-null constraints
- Check constraints
```

Do not assume browser validation is enough.

## 8.4 HTTP response consistency

Use one error-response format across the API.

```json
{
  "code": "VALIDATION_ERROR",
  "message": "The request could not be processed.",
  "requestId": "..."
}
```

Use correct HTTP status codes.

```text
200 OK: successful read or update
201 Created: successful creation
204 No Content: successful delete with no response body
400 Bad Request: malformed request
401 Unauthorized: missing or invalid authentication
403 Forbidden: authenticated but not allowed
404 Not Found: resource does not exist or should not be disclosed
409 Conflict: duplicate or conflicting state
422 Unprocessable Entity: valid request shape but invalid business state
429 Too Many Requests: rate limit reached
500 Internal Server Error: unexpected failure
```

---

# 9. GORM, pgx, and PostgreSQL Standards

## 9.1 GORM responsibilities

Use GORM for ordinary application persistence.

Use explicit queries.

```go
func (r *AssetRepository) GetByID(
    ctx context.Context,
    organizationID string,
    assetID string,
) (Asset, error) {
    var asset Asset

    err := r.db.WithContext(ctx).
        Where("organization_id = ? AND id = ?", organizationID, assetID).
        First(&asset).
        Error
    if err != nil {
        return Asset{}, err
    }

    return asset, nil
}
```

Rules:

* Always use `WithContext(ctx)`.
* Scope tenant-owned queries by `organization_id`.
* Avoid implicit global database state.
* Use explicit pagination.
* Use explicit ordering.
* Avoid accidental full-table scans.
* Avoid unbounded `Find` operations.
* Avoid `SELECT *` when only a small projection is needed.
* Avoid loading associations unless needed.
* Inspect generated SQL when debugging performance.
* Keep GORM-specific details inside repositories.

## 9.2 Use pgx intentionally

Use `pgx` for PostgreSQL-specific or performance-sensitive operations such as:

* Bulk operations
* `COPY`
* `LISTEN` / `NOTIFY`
* Specialized PostgreSQL types
* High-throughput read paths
* Performance-sensitive reporting
* SQL that is clearer as raw PostgreSQL

Do not mix GORM and pgx randomly.

For every feature, decide:

```text
GORM:
- Standard CRUD
- Conventional persistence
- Simple filtering and relations

pgx:
- PostgreSQL-specific behavior
- High-volume bulk work
- Hand-tuned SQL
- Advanced query patterns
```

## 9.3 Request transaction rules

HTTP request persistence uses request-scoped GORM transactions. Middleware begins the transaction, stores it in request context, commits successful requests, and rolls back failed requests.

Rules:

* Repositories should use the database handle from request context when present.
* Do not call `Begin`, `Commit`, or `Rollback` directly in repositories for the outer request transaction.
* Use nested `db.Transaction(...)` only when the operation needs an explicit multi-step boundary or savepoint behavior.
* Keep transactions short.
* Do not hold a request transaction open during slow external API calls when the operation can be reordered safely.
* Tests that change middleware or repository transaction behavior must cover commit and rollback outcomes.

If GORM and pgx must participate in the same business transaction, document the transaction strategy clearly. Do not assume separately-managed GORM and pgx calls are automatically atomic together.

## 9.4 pgx resource rules

When using `pgx`:

* Pass `context.Context`.
* Close rows.
* Check `rows.Err()`.
* Use `QueryRow` for one-row queries.
* Use connection pools intentionally.
* Keep transactions short.
* Always roll back unfinished transactions.
* Do not hold a transaction open during slow external API calls.
* Use parameterized queries.

Example:

```go
rows, err := pool.Query(ctx, query, organizationID)
if err != nil {
    return nil, fmt.Errorf("query vulnerabilities: %w", err)
}
defer rows.Close()

for rows.Next() {
    var vulnerability Vulnerability
    if err := rows.Scan(&vulnerability.ID, &vulnerability.CVEID); err != nil {
        return nil, fmt.Errorf("scan vulnerability: %w", err)
    }

    vulnerabilities = append(vulnerabilities, vulnerability)
}

if err := rows.Err(); err != nil {
    return nil, fmt.Errorf("iterate vulnerabilities: %w", err)
}
```

## 9.4 PostgreSQL migrations

Migrations must be:

* Small
* Reviewed
* Forward-focused
* Deterministic
* Safe for existing data
* Tested against realistic data volumes

Rules:

* Never edit a migration that has already been deployed.
* Create a new migration to correct a deployed schema.
* Use descriptive migration names.
* Add database constraints for important invariants.
* Add indexes based on real query patterns.
* Avoid destructive migrations without explicit approval.
* Backfill large data in controlled batches.
* Keep long-running migrations separate from deploy-critical migrations.
* Test indexes and query plans before production rollout.

Example:

```text
20260620_create_work_orders.up.sql
20260620_create_work_orders.down.sql
```

Use `EXPLAIN` during query review.

Use `EXPLAIN ANALYZE` carefully because it executes the statement.

## 9.5 Database constraints are required

Application validation is not enough.

Use PostgreSQL constraints for critical integrity.

Examples:

```sql
ALTER TABLE assets
    ADD CONSTRAINT assets_organization_id_fkey
    FOREIGN KEY (organization_id)
    REFERENCES organizations(id);

ALTER TABLE work_orders
    ADD CONSTRAINT work_orders_status_check
    CHECK (
        status IN (
            'open',
            'assigned',
            'in_remediation',
            'verified',
            'closed'
        )
    );

CREATE UNIQUE INDEX assets_organization_name_key
    ON assets (organization_id, name);
```

---

# 10. bcrypt and JWT Boundaries

## 10.1 Keep authentication code isolated

Password hashing and JWT behavior must not be scattered across handlers and services.

Prefer focused dependencies:

```go
type PasswordHasher interface {
    Hash(password string) (string, error)
    Compare(hashedPassword, password string) error
}

type TokenIssuer interface {
    Issue(user AuthenticatedUser) (string, error)
}

type TokenVerifier interface {
    Verify(token string) (AuthenticatedUser, error)
}
```

## 10.2 bcrypt rules

Use bcrypt only through a dedicated password-hashing service.

Do not:

* Hash passwords in handlers
* Compare passwords in repositories
* Log passwords
* Re-hash already hashed passwords
* Store plain-text passwords
* Repeat bcrypt configuration throughout the codebase

Good structure:

```text
auth/
  password_hasher.go
  jwt_issuer.go
  jwt_verifier.go
  service.go
```

## 10.3 JWT rules

JWT parsing, signing, validation, and claims mapping belong in one authentication package.

Use typed claims.

```go
type AccessTokenClaims struct {
    UserID         string   `json:"sub"`
    OrganizationID string   `json:"organizationId"`
    Roles          []string `json:"roles"`
    jwt.RegisteredClaims
}
```

Do not use untyped `map[string]any` claims throughout the application.

Middleware should translate a verified token into a trusted request-context identity.

Services should receive the authenticated identity through typed input or context helpers, not raw JWT strings.

---

# 11. Angular Architecture

## 11.1 Organize by feature

Preferred frontend structure:

```text
src/app/
  core/
    auth/
    api/
    interceptors/
    guards/
    config/

  shared/
    components/
    pipes/
    directives/
    models/

  features/
    assets/
      pages/
      components/
      data-access/
      models/
      assets.routes.ts

    vulnerabilities/
      pages/
      components/
      data-access/
      models/
      vulnerabilities.routes.ts

    work-orders/
      pages/
      components/
      data-access/
      models/
      work-orders.routes.ts
```

Rules:

* `core` contains application-wide singleton behavior.
* `shared` contains reusable presentation-focused code.
* `features` contains business functionality.
* Avoid placing feature-specific logic inside `shared`.
* Keep route definitions near their feature.
* Keep API access close to the feature that owns it.

## 11.2 Components should have focused responsibilities

A component should primarily:

* Render UI
* Receive input
* Emit user intent
* Coordinate small UI behavior

Avoid putting large business workflows inside components.

Split large components into:

```text
Container/page component:
- Coordinates route data, stores, API calls, and feature state

Presentation component:
- Receives typed inputs
- Emits typed outputs
- Contains limited UI logic
```

Do not create separate components just to wrap one HTML element.

## 11.3 Angular services

Services should have clear responsibilities.

Good:

```text
AssetApiService
AssetStore
WorkOrderApiService
WorkOrderWorkflowService
AuthenticationService
NotificationService
```

Avoid:

```text
AppService
DataService
UtilityService
SharedService
CommonService
```

Separate API communication from UI state.

Example:

```text
AssetApiService:
- HTTP requests to asset endpoints

AssetStore:
- Feature state
- Loading state
- Selected asset state
- Derived UI state

AssetPageComponent:
- Coordinates route and UI behavior
```

## 11.4 Dependency injection

Use Angular dependency injection rather than manually creating services.

Do not instantiate services with `new` inside components.

Bad:

```ts
const api = new AssetApiService();
```

Better:

```ts
private readonly assetApi = inject(AssetApiService);
```

Keep injected dependencies minimal.

A component or service with many injected dependencies may have too many responsibilities.

---

# 12. TypeScript Standards

## 12.1 Use strict TypeScript

Enable and preserve strict compiler settings.

Recommended baseline:

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

Do not disable strictness to make compilation easier.

Fix the type issue instead.

## 12.2 Avoid `any`

Do not use `any` unless there is a documented and unavoidable interoperability reason.

Prefer:

```ts
unknown
never
Record<string, unknown>
readonly
discriminated unions
type guards
mapped types
generics
```

Bad:

```ts
function parseResponse(data: any): any {
  return data;
}
```

Better:

```ts
function isAssetResponse(value: unknown): value is AssetResponse {
  return typeof value === 'object' && value !== null && 'id' in value;
}
```

## 12.3 Use discriminated unions for state

Good:

```ts
type LoadState<T> =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; data: T }
  | { status: 'error'; message: string };
```

Avoid unrelated booleans that can conflict:

```ts
isLoading = false;
hasLoaded = false;
hasError = false;
```

A single typed state is easier to reason about.

## 12.4 Keep types close to their feature

Feature DTOs and models should live with the feature that owns them.

```text
features/assets/models/asset-response.ts
features/assets/models/create-asset-request.ts
features/assets/models/asset-filter.ts
```

Do not create a giant `models/` folder containing every application type.

---

# 13. RxJS Standards

## 13.1 Avoid nested subscriptions

Nested subscriptions are not allowed.

Bad:

```ts
this.assetId$.subscribe((assetId) => {
  this.assetApi.getById(assetId).subscribe((asset) => {
    this.asset = asset;
  });
});
```

Better:

```ts
readonly asset$ = this.assetId$.pipe(
  distinctUntilChanged(),
  switchMap((assetId) => this.assetApi.getById(assetId)),
);
```

## 13.2 Name streams with `$`

Observable names must end with `$`.

```ts
readonly asset$ = ...
readonly vulnerabilities$ = ...
readonly selectedAssetId$ = ...
readonly isLoading$ = ...
```

Do not add `$` to plain values.

```ts
const asset = await firstValueFrom(this.asset$);
```

## 13.3 Choose the correct mapping operator

Use the correct RxJS operator intentionally.

```text
switchMap:
- Latest request wins
- Search fields
- Route changes
- Filter changes

concatMap:
- Preserve request order
- Sequential writes
- Workflow updates that must happen one at a time

mergeMap:
- Independent concurrent work
- Use intentional concurrency limits when needed

exhaustMap:
- Ignore duplicate triggers while an action is running
- Submit buttons
- Login forms
```

## 13.4 Avoid manual subscriptions when possible

Prefer the Angular `async` pipe or signal interop where appropriate.

When a manual subscription is required, make cleanup explicit.

Use Angular lifecycle-aware cleanup such as `takeUntilDestroyed()`.

Do not leave subscriptions running after a component is destroyed.

## 13.5 Keep subjects private

Expose observables or read-only state, not mutable subjects.

Bad:

```ts
readonly selectedAssetSubject = new BehaviorSubject<Asset | null>(null);
```

Better:

```ts
private readonly selectedAssetSubject = new BehaviorSubject<Asset | null>(null);

readonly selectedAsset$ = this.selectedAssetSubject.asObservable();
```

---

# 14. Angular SSR and Node/Express Standards

## 14.1 SSR-safe frontend code

Angular SSR code can run on the server and browser.

Do not assume browser-only APIs exist.

Do not access these at module load time:

```text
window
document
localStorage
sessionStorage
navigator
location
history
WebSocket
```

Use platform-aware patterns when browser access is required.

```ts
if (isPlatformBrowser(this.platformId)) {
  localStorage.setItem('key', 'value');
}
```

Do not store request-specific data in global module variables or singleton server state.

That can leak data between users during SSR.

## 14.2 Keep SSR server logic thin

The Express SSR server should mainly:

* Configure server middleware
* Serve static files
* Delegate rendering to Angular
* Handle health checks
* Apply global error handling
* Shut down gracefully

Do not place feature business rules in Express route files.

Do not duplicate Go API business logic in Node/Express.

The Go API remains the business backend.

## 14.3 Express middleware rules

Middleware must have one clear purpose.

Good middleware categories:

```text
request ID
logging
authentication forwarding
rate limiting
compression
static assets
SSR rendering
error handling
```

Order middleware intentionally.

Error middleware belongs after routes.

Use a central error handler.

```ts
app.use((error: Error, req: Request, res: Response, next: NextFunction) => {
  logger.error({ error, requestId: req.id }, 'unexpected SSR server error');

  res.status(500).send('Internal server error');
});
```

Do not return stack traces to users.

## 14.4 Node process rules

* Do not rely on unhandled promise rejections for normal error handling.
* Catch errors at request and job boundaries.
* Shut down gracefully on termination signals.
* Close servers, pools, queues, and background jobs during shutdown.
* Do not block the event loop with large synchronous work.
* Keep environment loading inside configuration modules.
* Validate required environment variables during startup.

---

# 15. Testing Standards

## 15.1 Test behavior, not implementation details

Tests should verify observable behavior.

Good test targets:

* Service business rules
* Workflow transitions
* Authorization outcomes
* Repository persistence behavior
* API status codes and response bodies
* Component user interactions
* Loading and error states
* SSR-safe rendering behavior

Avoid tests that only prove private implementation details.

Bad:

```ts
expect(component['assetApi']).toBeDefined();
```

Better:

```ts
await user.click(screen.getByRole('button', { name: /create asset/i }));

expect(assetApi.create).toHaveBeenCalledWith(expectedRequest);
expect(screen.getByText(/asset created/i)).toBeVisible();
```

## 15.2 Go testing

Use table-driven tests when several input/output cases share behavior.

```go
func TestWorkOrderService_Close(t *testing.T) {
    tests := []struct {
        name    string
        input   CloseWorkOrderInput
        wantErr error
    }{
        {
            name:    "rejects unverified work order",
            input:   CloseWorkOrderInput{Status: WorkOrderStatusOpen},
            wantErr: ErrWorkOrderNotVerified,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test behavior.
        })
    }
}
```

Test levels:

```text
Unit tests:
- Pure business rules
- Validation
- Workflow transitions
- Mapping

Repository integration tests:
- GORM queries
- pgx queries
- PostgreSQL constraints
- Migrations
- Transactions

HTTP tests:
- Request validation
- Authentication behavior
- Authorization
- Status codes
- Response shape
```

Use `httptest` for Go HTTP tests.

## 15.3 Vitest rules

Use Vitest for Angular and TypeScript unit tests.

Rules:

* Test one meaningful behavior per test.
* Use descriptive names.
* Reset mocks between tests.
* Mock external boundaries, not the code under test.
* Avoid large global mock setups.
* Prefer interaction-based UI tests.
* Use fake timers only when time behavior matters.
* Keep tests deterministic.
* Avoid test order dependencies.

Good names:

```ts
it('shows a validation message when the asset name is empty', () => {});
it('does not allow an analyst to close an unverified work order', () => {});
it('cancels stale vulnerability searches when the filter changes', () => {});
```

## 15.4 Mocking rules

Mock:

* Network requests
* External APIs
* Time
* Random ID generation
* Email delivery
* File storage
* Third-party SDKs

Do not mock:

* The function you are trying to test
* Simple domain objects
* Pure utility functions
* The database in repository integration tests
* The entire framework unless necessary

Inject non-deterministic dependencies where possible:

```text
Clock
IDGenerator
EmailClient
NVDClient
AuditLogger
TokenIssuer
PasswordHasher
```

## 15.5 Test data

Use explicit test fixtures.

Bad:

```ts
const asset = { id: '1', name: 'test' } as Asset;
```

Better:

```ts
function createAsset(overrides: Partial<Asset> = {}): Asset {
  return {
    id: 'asset-001',
    organizationId: 'organization-001',
    name: 'Production API Server',
    assetType: 'server',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    ...overrides,
  };
}
```

Keep test factories near the relevant feature.

---

# 16. Refactoring Rules

Refactor only when it improves at least one of these:

* Readability
* Testability
* Separation of responsibilities
* Duplication reduction
* Error handling
* Performance based on evidence
* Security
* Maintainability

Do not refactor for personal style preference alone.

Use safe refactoring steps:

1. Add or confirm tests.
2. Make a small isolated change.
3. Run relevant tests.
4. Repeat.
5. Keep behavior unchanged unless the task requires a behavior change.

Do not combine a behavior change and a large refactor in the same change unless unavoidable.

---

# 17. Definition of Done

A change is complete only when:

* [ ] The smallest reasonable scope was used.
* [ ] Naming is clear and follows project conventions.
* [ ] Functions have focused responsibilities.
* [ ] Normal business flow uses guard clauses instead of nested `if` statements.
* [ ] No unnecessary abstraction was added.
* [ ] Request, domain, persistence, and response models are separated where needed.
* [ ] Errors are wrapped internally and safely mapped externally.
* [ ] New or changed behavior has tests.
* [ ] Existing tests still pass.
* [ ] No secrets, debug code, commented-out code, or temporary hacks remain.
* [ ] Comments explain decisions or constraints, not obvious statements.
* [ ] Database changes have reviewed migrations and appropriate constraints.
* [ ] API changes preserve tenant scope, authorization, and response consistency.
* [ ] Angular code remains SSR-safe.
* [ ] RxJS code has no nested subscriptions.
* [ ] Dependencies were not changed without approval.
* [ ] Security requirements in `SECURITY.md` are still satisfied.

---

# 18. Recommended Quality Commands

Only run commands already supported by the repository, and inspect `package.json`, `Makefile`, scripts, and CI configuration first.

Typical backend checks:

```bash
go fmt ./...
go test ./...
go vet ./...
go test -race ./...
```

Typical frontend checks:

```bash
npm run lint
npm run test -- --run
npm run build
```

Do not use `npx`, install packages, update packages, regenerate lockfiles, or run auto-fix commands without approval.

Do not run commands that modify database state, production-like data, cloud resources, dependencies, or CI/CD configuration without permission.

---

# 19. Official References

## Go

* [Effective Go](https://go.dev/doc/effective_go)
* [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments)
* [Go Doc Comments](https://go.dev/doc/comment)
* [Go Testing Comments](https://go.dev/wiki/TestComments)
* [Go Security Documentation](https://go.dev/doc/security/)

## Gin

* [Gin Documentation](https://gin-gonic.com/en/docs/)
* [Gin Binding and Validation](https://gin-gonic.com/en/docs/binding/binding-and-validation/)
* [Gin Custom Validators](https://gin-gonic.com/en/docs/binding/custom-validators/)

## GORM, pgx, PostgreSQL

* [GORM Documentation](https://gorm.io/docs/)
* [GORM Security Guidance](https://gorm.io/docs/security.html)
* [pgx Documentation](https://pkg.go.dev/github.com/jackc/pgx/v5)
* [PostgreSQL Transactions](https://www.postgresql.org/docs/current/tutorial-transactions.html)
* [PostgreSQL Transaction Isolation](https://www.postgresql.org/docs/current/transaction-iso.html)
* [PostgreSQL Indexes](https://www.postgresql.org/docs/current/sql-createindex.html)
* [PostgreSQL EXPLAIN](https://www.postgresql.org/docs/current/sql-explain.html)
* [PostgreSQL Query Planning](https://www.postgresql.org/docs/current/using-explain.html)

## Authentication

* [Go bcrypt Package](https://pkg.go.dev/golang.org/x/crypto/bcrypt)
* [golang-jwt/jwt v5](https://pkg.go.dev/github.com/golang-jwt/jwt/v5)
* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
* [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

## Angular, TypeScript, RxJS, Node, Express, Vitest

* [Angular Coding Style Guide](https://angular.dev/style-guide)
* [Angular Testing Guide](https://angular.dev/guide/testing)
* [Angular SSR Guide](https://angular.dev/guide/ssr)
* [Angular HTTP Guide](https://angular.dev/guide/http/making-requests)
* [Angular Security Best Practices](https://angular.dev/best-practices/security)
* [TypeScript TSConfig Reference](https://www.typescriptlang.org/tsconfig/)
* [TypeScript Strict Mode](https://www.typescriptlang.org/tsconfig/strict.html)
* [RxJS Documentation](https://rxjs.dev/guide/overview)
* [Node.js Error Handling](https://nodejs.org/api/errors.html)
* [Express Error Handling](https://expressjs.com/en/guide/error-handling/)
* [Express Middleware](https://expressjs.com/en/guide/writing-middleware/)
* [Vitest Testing Guide](https://vitest.dev/guide/)
* [Vitest Mocking Guide](https://vitest.dev/guide/mocking)
