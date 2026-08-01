# 🖥️ Assets

## 🧭 Overview

An asset is a user-owned inventory record representing a device, application, service, or other managed technology. The feature combines identity, product metadata, business criticality, assessment metadata, and derived risk state.

## 🎯 Purpose

The asset model gives the rest of the system a stable record to attach vulnerabilities, CPE matches, and future remediation workflows to. It keeps inventory facts separate from the conclusions produced by matching and risk workflows.

## 🧱 Data Shape

The core asset fields are name, type, vendor, product, version, operating system, device model, owner, and criticality. The asset also exposes derived `riskLevel` and a linked assessment containing risk score and CPE review metadata.

Ownership, audit fields, risk state, and assessment identifiers are backend-controlled. Clients submit only the allowed inventory fields.

## 🔌 Current API

```text
GET    /api/assets
GET    /api/assets/:id
POST   /api/assets
PUT    /api/assets/:id
DELETE /api/assets/:id
```

Relationship and matching routes are documented separately in [asset-vulnerability-assignment.md](asset-vulnerability-assignment.md) and [ai-cpe-and-cve-matching.md](ai-cpe-and-cve-matching.md).

## 🔄 Lifecycle

Manual creation validates and persists the submitted asset. AI-assisted creation accepts bounded raw text, asks the backend-owned prompt to extract a draft, validates the result, and then follows the normal asset creation path.

Reads and updates are scoped to the authenticated user. Deletes are transactional and clean up related assessment and relationship state according to the persistence rules.

Asset risk is derived from active assigned vulnerabilities. Asset creation does not invent risk, and AI ingestion does not attach CVEs automatically.

## 🧩 Architecture

```text
asset controller -> asset service -> asset repository -> PostgreSQL
                                      |
                                      -> asset assessment
```

The asset service owns validation, normalization, ownership, duplicate checks, and AI orchestration. The repository owns persistence. Risk, assignment, NVD, and AI matching are separate boundaries that enrich the asset.

## 🛡️ Security Invariants

- Ownership comes from authenticated server state.
- Input is validated before persistence or external processing.
- AI output is treated as untrusted data.
- Duplicate identity records are rejected within the user’s scope.
- Browser input cannot set risk, role, user ID, or assessment ownership.

Shared trust and error rules are defined in [security-boundaries.md](security-boundaries.md) and [api-error-handling.md](api-error-handling.md).

## 🎭 Walkthrough: Asset Ownership

1. Alice creates an asset; Bob is a different authenticated user.
2. Alice’s asset is returned to Alice but not to Bob.
3. The service handles an asset create or read request.
4. The controller accepts the HTTP contract, the service validates ownership rules, and the repository scopes persistence by the authenticated owner.
5. Asset identifiers must not become a way to cross user boundaries.
6. The server assigns ownership from authenticated context, rejects client-supplied ownership fields, and includes the owner predicate in reads, updates, and deletes.

## 🚧 Current Limitations

- Ownership is user-scoped rather than organization-scoped.
- The frontend asset workflow is still evolving.
- Risk score and risk level are separate concepts; the current asset-risk service derives `riskLevel`, not `AssetAssessment.RiskScore`.
- Audit history, remediation workflows, and organization-wide asset views are future work.

## 🔑 Key Terms

- **Asset:** A managed technology inventory record.
- **Asset assessment:** Mutable risk and CPE matching metadata linked to an asset.
- **Criticality:** Business importance supplied as asset metadata.
- **Derived state:** A value calculated from other persisted records rather than trusted client input.
