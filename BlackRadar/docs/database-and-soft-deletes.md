# 🗄️ Database And Soft Deletes

## 🧭 Overview

BlackRadar uses PostgreSQL with GORM for persistence. Database behavior is organized around user-scoped records, explicit relationships, derived asset state, and soft deletion for recoverable or audit-relevant data.

## 🧱 Core Schema

The primary tables are:

- `users`: identities and roles
- `refresh_sessions`: server-side refresh-session state
- `assets`: inventory records and derived `risk_level`
- `asset_assessments`: risk score and CPE matching metadata
- `vulnerabilities`: user-owned vulnerability records
- `asset_vulnerabilities`: the asset-to-vulnerability relationship

The relationship table is the source of active assignment state. It contains `asset_id`, `vulnerability_id`, `created_at`, and `deleted_at`.

## 🧬 Model Boundaries

Persistence models live in `api/model`. The asset model owns core inventory fields, the linked assessment, and the many-to-many vulnerability relationship. DTOs remain in controller packages so browser contracts are not treated as database contracts.

## ♻️ Soft Deletion

Soft deletion records a timestamp instead of immediately removing a row. Normal queries exclude rows with `deleted_at` set. The relationship table also has an active-only uniqueness rule for `(asset_id, vulnerability_id)`, allowing historical links while preventing duplicate active links.

Relationship queries must explicitly include `deleted_at IS NULL` where the join is written manually. A historical relationship must not influence current asset risk.

## 🔄 Transaction Model

Services own multi-step transaction boundaries. Repositories execute against the request-scoped database handle, including a transaction when one is present.

Assignment, removal, vulnerability changes, and risk refreshes use one transaction context where consistency requires it. An error rolls the operation back; a nil result commits it.

## 🛠️ Runtime Schema

Startup currently runs GORM `AutoMigrate` and guarded SQL statements from `api/platform/db`. This is local/runtime provisioning. Reviewed versioned migrations remain the production-hardening direction.

## 🔐 Data Safety

Queries must use parameterized values and ownership predicates. `Unscoped` access is reserved for explicit cleanup, recovery, retention, or test paths. Database constraints reinforce invariants but do not replace authorization checks.

See [security-boundaries.md](security-boundaries.md) for the application trust model and [api-error-handling.md](api-error-handling.md) for persistence error translation.

## 🎭 Walkthrough: Removing An Assignment

- **Who:** Alice is an authorized administrator managing one of her assets.
- **What:** Alice removes an asset-vulnerability relationship.
- **When:** The assignment removal request is processed as a multi-step write.
- **Where:** The service owns the transaction and business rules; repositories update the bridge row and related records.
- **Why:** The relationship should leave an auditable inactive row while active queries stop treating it as attached.
- **How:** The bridge row is soft-deleted, dependent cleanup and risk refresh use the same transaction context, and any error rolls the entire operation back.

## 🔑 Key Terms

- **Soft delete:** Retaining a row while marking it inactive with `deleted_at`.
- **Active relationship:** A bridge row whose `deleted_at` value is null.
- **Partial unique index:** A uniqueness rule applied only to rows meeting a condition.
- **Request-scoped database:** The GORM handle attached to the current request or transaction.
