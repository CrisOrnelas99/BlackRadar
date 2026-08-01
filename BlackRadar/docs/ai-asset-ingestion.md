# 🤖 AI Asset Ingestion

## 🧭 Overview

AI asset ingestion converts bounded raw text into a candidate asset draft. It is an input convenience, not an autonomous inventory authority.

```text
raw text -> backend prompt -> structured draft -> normal asset validation -> persistence
```

## 🎯 Purpose

Users may describe an asset in natural language or imported text. The backend extracts useful inventory fields while preserving the same validation, ownership, and duplicate rules used by manual creation.

## 🔌 Current API

```text
POST /api/assets
```

The request selects AI mode and supplies `rawText`. The browser does not call OpenAI directly.

## 🧱 Boundary Design

- The backend owns the prompt, model configuration, provider credentials, output schema, limits, and validation.
- Raw text is treated as untrusted input and is bounded, normalized, and checked for unsafe instruction-like content.
- Before the structured prompt leaves the backend, common secrets and direct identifiers are redacted from the payload. This is defense in depth, not a guarantee that every piece of PII is removed.
- The model is required to return JSON matching the backend-owned shape.
- The resulting draft passes through ordinary asset validation and ownership assignment.

Asset ingestion remains owned by the asset service. The separate `service/ai` package is used for admin diagnostic prompts, not for asset persistence or matching decisions.

AI output cannot set user ID, role, risk state, assessment ownership, or arbitrary database fields.

## 🔄 Workflow

1. The asset controller binds the request.
2. The asset service sanitizes and bounds the raw text.
3. The backend sends the text to the configured OpenAI client with a locked extraction prompt.
4. The response is decoded as strict JSON and rejected when malformed or structurally unexpected.
5. Safe defaults are applied where permitted.
6. The normal asset service validates duplicates and persists the asset.

Ingestion does not automatically perform CPE matching or attach CVEs. Those are separate workflows.

## 🎯 Advisory Model

The model may extract facts present in the input, but it must not invent product identity, vulnerabilities, CPEs, or CVEs. Human review and later matching remain responsible for security conclusions.

## 🎭 Walkthrough: Alice Imports An Asset Description

1. Alice submits a description of a device; Bob is not involved in the resulting draft.
2. The backend turns raw text into a structured asset draft.
3. Alice uses the AI-assisted ingestion endpoint.
4. The controller accepts the request, the service validates bounded input, and the backend-owned provider client invokes the model.
5. AI can reduce data-entry effort, but it must not decide ownership or create unverified security state.
6. The server-owned prompt produces a candidate, the response is validated and normalized, and Alice must still use the normal asset workflow before persistence.

## 🚧 Current Limitations

- AI ingestion creates one asset draft per request.
- Prompt injection defenses are bounded input controls, not a guarantee that external text is safe.
- No automatic vulnerability attachment occurs during ingestion.
- Provider availability, latency, and model output quality remain dependency risks.

See [security-boundaries.md](security-boundaries.md) and [api-error-handling.md](api-error-handling.md) for shared controls.

## 🔑 Key Terms

- **Ingestion:** Converting external or free-form input into internal application data.
- **Draft:** A proposed structured asset before normal persistence validation.
- **Prompt injection:** Input attempting to alter the model’s assigned task or rules.
- **Advisory AI:** AI output that informs a workflow but cannot authorize or persist itself.
