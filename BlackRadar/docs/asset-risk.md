# 📊 Asset Risk

## 🧭 Overview

Asset risk is a backend-derived property of an asset. The current implementation combines asset criticality with the highest severity among its active assigned vulnerabilities.

```text
asset criticality + highest active severity -> averaged 1-4 score -> asset risk level
```

The levels are scored as `Low=1`, `Medium=2`, `High=3`, and `Critical=4`. An asset with no active vulnerabilities always has Low risk. When vulnerabilities are present, the asset criticality score is averaged with the highest active vulnerability severity score, with .5 values rounded upward. Unknown values currently map to Low.

## 🎯 Purpose

The service keeps risk from becoming a client-controlled or duplicated calculation. Assignment, vulnerability changes, and approved AI matching all use the same scoring rule.

## 🧩 Architecture

```text
asset-risk service
  -> deterministic scoring support
  -> asset-risk repository
  -> PostgreSQL assets.risk_level
```

The service owns calculation and orchestration. The repository loads active, organization-scoped vulnerabilities and persists the result. The request-scoped transaction is reused when risk is part of a larger workflow.

## 🔄 Refresh Events

- Assignment or removal refreshes the affected asset.
- Vulnerability updates or deletes refresh every actively assigned asset.
- Approved CPE matching refreshes risk after bounded CVE attachment.

Each workflow recalculates from the complete active vulnerability set, not only the changed record.

## 🔐 Security And Consistency

Risk is not accepted from the browser. The service obtains the user scope from authenticated request state, and the repository applies ownership predicates to both sides of the relationship. Soft-deleted bridge rows are excluded.

When a relationship and risk update are coupled, the service transaction either commits both or rolls both back. Error translation follows [api-error-handling.md](api-error-handling.md).

## 🎭 Walkthrough: Risk Changes

1. Alice owns an asset with one active High vulnerability; Bob owns a separate asset.
2. Alice removes the High vulnerability and the asset risk changes.
3. The relationship removal workflow completes.
4. The asset-risk service recalculates the asset, and its repository persists `Asset.RiskLevel`.
5. Risk is derived from the complete active relationship set, so it must change when the set changes.
6. The service loads Alice’s remaining active vulnerabilities, selects the highest normalized severity, combines it with the asset criticality, writes the result in the same transaction, and leaves Bob’s asset untouched.

## 🧮 Current Data Distinction

`Asset.RiskLevel` is the current derived level. `AssetAssessment.RiskScore` is a separate persisted field and is not currently calculated by this service. Asset criticality is an input to the current risk rule but remains separately displayed as inventory metadata.

## 🚧 Current Limitations

- The calculation uses asset criticality plus the highest vulnerability severity, with Low as the minimum risk level.
- Unknown severities default to Low.
- No risk history, explanation, scoring version, or per-vulnerability contribution is stored.
- Organization-wide aggregation and formal risk models are future work.

## 🔑 Key Terms

- **Risk level:** The derived Low-to-Critical classification stored on an asset.
- **Active vulnerability:** A vulnerability linked through a non-deleted bridge row.
- **Derived field:** Persisted state calculated from other accepted records.
