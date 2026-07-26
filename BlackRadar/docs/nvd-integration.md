# 🛰️ NVD Integration

## 🧭 Overview

BlackRadar uses the National Vulnerability Database as its external reference for CVE and CPE information. The integration is a backend provider boundary, not a browser data source.

## 🔌 Current Routes

```text
GET /api/nvd/cves/:cveId
```

The direct route is currently restricted to the admin route group. Internal matching calls use the same backend-only provider boundary.

Internal asset matching also uses backend NVD clients for CPE candidate and CVE searches.

## 🧱 Provider Boundary

The NVD client owns endpoint configuration, HTTP timeouts, redirect policy, response-size limits, retry behavior, API-key handling, rate limiting, and provider response mapping. Services own validation, authorization, and workflow meaning.

NVD responses are converted into safe internal DTOs. Raw provider bodies and headers are not returned to clients.

## 🔄 Lookup Workflows

Direct CVE lookup validates and normalizes the identifier before requesting the official NVD endpoint. CPE and CVE searches are invoked internally by matching workflows and remain bounded by server-controlled limits.

The browser never supplies a provider URL, API key, unrestricted query, or authoritative vulnerability record.

## ⏱️ Reliability Controls

The current client uses bounded request timeouts, a response body cap, constrained retries for selected transient failures, and process-local rate limiting. Deployments with multiple backend instances require a shared rate-limit mechanism for global enforcement.

## 🛡️ Security And Errors

Provider errors are translated at the external-client boundary and then mapped to service categories. Invalid identifiers, not found, rate limited, unavailable, and malformed responses remain distinguishable internally while browser responses stay safe.

See [security-boundaries.md](security-boundaries.md) and [api-error-handling.md](api-error-handling.md).

## 🎭 Walkthrough: CVE Lookup

- **Who:** Alice requests vulnerability information for an asset; Bob cannot use Alice's request to change the provider scope.
- **What:** BlackRadar looks up a CVE or CPE through NVD.
- **When:** A protected backend workflow needs authoritative provider data.
- **Where:** The NVD client owns outbound HTTP behavior; services own validation and local persistence; the browser never calls NVD.
- **Why:** Centralizing provider access protects credentials, enforces rate limits, and keeps external data behind application validation.
- **How:** The service validates the identifier, the client sends a bounded request, the response is checked, and only accepted fields are mapped into local state or a safe service error.

## 🚧 Current Limitations

- NVD availability and rate limits remain external dependencies.
- Local records are not a complete historical synchronization system.
- CPE matching is advisory and may require review.
- Background refresh and organization-wide synchronization are planned.

## 🔑 Key Terms

- **NVD:** The National Vulnerability Database provider used for CVE and CPE reference data.
- **CVE:** A standardized vulnerability identifier.
- **CPE:** A standardized product/platform identifier.
- **Provider boundary:** The adapter that isolates external protocol behavior from application services.
- **Rate limit:** A server-enforced bound on provider requests.
