# 🐞 Vulnerabilities

## 🧭 Overview

A vulnerability is an organization-scoped record describing a security issue, commonly identified by a CVE. It stores normalized local data so asset workflows do not depend on a live provider response for every read.

## 🎯 Purpose

The vulnerability feature provides the local representation used by assignment, risk calculation, review, and future remediation workflows. NVD may supply authoritative CVE evidence, but local persistence controls application ownership and relationships.

## 🔌 Current API

```text
GET    /api/vulnerabilities
GET    /api/vulnerabilities/:id
POST   /api/vulnerabilities
PUT    /api/vulnerabilities/:id
DELETE /api/vulnerabilities/:id
```

Mutation routes are admin-only. Reads are available to authenticated users in the current organization.

## 🧱 Data Shape

The record contains `cveId`, title, severity, description, status, ownership, audit metadata, and an optional `nvdPublishedAt` timestamp for CVE data imported from NVD. CVE IDs are normalized and validated. Duplicate CVE records are rejected within the user’s scope.

## 🔄 Lifecycle

Creation validates and persists a local record. Approved CPE scans create or refresh local CVE records by CVE ID and preserve the local status while recording NVD's publication timestamp when available. Reads return only records in the authenticated user’s scope. Updates preserve the record identity and refresh the risk of every actively assigned asset. Deleting a vulnerability removes its active relationships and refreshes affected assets within the transaction boundary.

The vulnerability service owns role checks, validation, duplicate rules, and orchestration. The repository owns persistence and database constraints.

## 🔗 Relationship To Risk

Existence alone does not change an asset’s risk. The active bridge relationship determines whether a vulnerability contributes to an asset. When severity or assignment state changes, the `asset_risk` service recalculates each affected asset.

See [asset-vulnerability-assignment.md](asset-vulnerability-assignment.md) and [asset-risk.md](asset-risk.md) for relationship and scoring behavior.

## 🎭 Walkthrough: Alice Updates A Vulnerability

1. Alice is an authorized administrator; Bob is not allowed to alter Alice’s vulnerability records.
2. Alice updates the local severity or status of a vulnerability.
3. The update request reaches the protected vulnerability route.
4. The controller binds the request, the service validates the change, and the repository persists it before affected asset risk is refreshed.
5. Local records support application workflows, while their severity may contribute to the derived risk of linked assets.
6. The backend checks authorization and valid values, saves the update transactionally, recalculates affected assets, and returns a safe error if any step fails.

## 🛡️ Security Invariants

- Vulnerability organization scope is derived from the authenticated principal.
- Admin authorization is enforced by middleware and service/repository checks.
- NVD data is validated before becoming local application state.
- Raw provider or database errors do not become browser responses.
- Deletion and risk refresh remain consistent through transactions.

## 🚧 Current Limitations

- Vulnerability management is admin-only.
- The current deployment uses one organization; department and multi-organization isolation are future work.
- Status is stored but does not currently represent a complete remediation workflow.
- Audit events, exceptions, work orders, and automated refresh are future capabilities.

## 🔑 Key Terms

- **CVE:** A standardized identifier for a publicly disclosed vulnerability.
- **Severity:** The normalized impact classification stored on a vulnerability.
- **Local vulnerability:** Application-owned persisted vulnerability data.
- **NVD published at:** The publication timestamp supplied by NVD for an imported CVE, when available.
- **Affected asset:** An asset with an active relationship to the vulnerability.
