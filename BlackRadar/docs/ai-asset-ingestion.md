# 🤖 Future AI Asset Ingestion

## 🧭 Status

Single-asset AI creation is intentionally not exposed by the current API. Manual asset creation is the current path for one asset, while AI-assisted asset work is reserved for a future batch workflow.

## 🎯 Future Purpose

The planned workflow will accept large pasted text or uploaded files containing multiple asset descriptions, extract candidate assets, and let a user review the candidates before anything is persisted.

```text
large text or file -> backend extraction -> candidate assets -> user review -> persistence
```

## 🔒 Boundary Design

- The backend will own prompts, provider credentials, input limits, output validation, and persistence authorization.
- Uploaded or pasted content will remain untrusted input.
- AI output will be advisory and will not set ownership, roles, risk state, assessment ownership, or arbitrary database fields.
- NVD remains the source of truth for CPE and CVE data; AI matching must use bounded NVD candidates.

## 🚧 Planned Work

- Add bounded batch raw-text input.
- Add safe file-content input.
- Extract multiple candidate assets rather than one asset per request.
- Add a review and correction step before persistence.
- Preserve user ownership and duplicate checks through the normal asset service.

The current backend still supports AI-assisted product fingerprinting and NVD CPE/CVE matching for saved assets. Those workflows are separate from future batch asset ingestion.

See [assets.md](assets.md), [ai-cpe-and-cve-matching.md](ai-cpe-and-cve-matching.md), and [security-boundaries.md](security-boundaries.md) for current asset and matching behavior.

## 🔑 Key Terms

- **Batch ingestion:** Processing multiple asset descriptions from one text or file input.
- **Candidate asset:** An AI-proposed record awaiting user review.
- **Advisory AI:** AI output that cannot authorize or persist security state by itself.
