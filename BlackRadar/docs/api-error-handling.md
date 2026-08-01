# ⚠️ API Error Handling

## 🧭 Overview

BlackRadar uses a layered error model so implementation details stay inside the backend while clients receive stable, safe responses.

The contract is:

```text
database/provider failure
  -> repository or external sentinel
  -> service error category
  -> controller status mapping
  -> HandleError safe JSON
```

## 🧩 Layer Responsibilities

### 🗃️ Repository And External Boundaries

Repositories translate GORM, PostgreSQL, and constraint outcomes into component-owned errors such as not found, duplicate, invalid reference, or persistence failure. External clients do the equivalent for provider, timeout, rate-limit, and malformed-response outcomes.

Underlying causes are wrapped with `%w` so services and tests can use `errors.Is` or `errors.As` without exposing the cause to the client.

### ⚙️ Service Boundary

Services convert lower-level errors into business categories such as validation, conflict, forbidden, not found, dependency, or internal failure. They own the workflow meaning and transaction outcome.

### 🌐 Controller Boundary

Controllers classify service errors and call the shared `HandleError` path. They do not import repository implementations or decide how database errors map to HTTP behavior.

## 📦 Response Contract

The client receives a safe response containing a stable error code, a user-facing message, and a request ID. The response must not contain SQL, stack traces, JWT internals, passwords, tokens, API keys, or raw provider bodies.

## 🔄 Transaction Behavior

A transaction-owning service returns the error that should trigger rollback. Services request the transaction through `platform/transaction`, while `platform/db` implements it with GORM. Multi-step workflows, such as relationship assignment plus risk refresh, use the same request-scoped database session so a partial success cannot be committed.

## 🧪 Testing Expectations

Error tests should verify both layers of the contract:

- the expected service category is detectable
- the underlying repository or external cause remains detectable through wrapping

Feature documents describe workflow-specific failures only when they add information beyond this shared contract.

## 🎭 Walkthrough: A Missing Asset

1. Alice is authenticated and requests an asset that does not belong to her.
2. The lookup produces a not-found or ownership-safe result.
3. The request reaches the repository during the service call.
4. The repository classifies the persistence result, the service preserves the business meaning, and the controller maps it to the public response.
5. The client needs a stable safe response without learning database details or another user’s data.
6. The error is wrapped internally, classified with `errors.Is` or `errors.As`, and returned through the shared error handler with a safe code, message, and request ID.

## 🔑 Key Terms

- **Sentinel error:** A stable error value used for classification.
- **Error category:** A service-level meaning such as conflict or forbidden.
- **Error wrapping:** Preserving a lower-level cause with `%w`.
- **HandleError:** The shared controller path for safe API error responses.
