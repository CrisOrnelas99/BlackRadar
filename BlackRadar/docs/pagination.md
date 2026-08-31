# 📄 Pagination

## 🧭 Overview

BlackRadar uses server-side pagination for the authenticated asset inventory. The backend returns a bounded asset page together with metadata that lets Angular render consistent table controls. The shared pagination contract lives in `api/common/pagination`.

The current asset table displays six rows per page. The page size is a backend policy, not a value trusted from the browser.

## 🎯 Purpose

Pagination keeps inventory responses small as a user's asset list grows while preserving correct filtering, sorting, ownership checks, and total counts. Filters and sorting are applied in the database before the total is counted and before the requested page is selected.

## 🔌 Current API

`GET /api/assets` accepts the current page and asset list filters:

```text
GET /api/assets?page=2&search=server&sortField=name&sortDirection=asc
```

The response is shaped as:

```json
{
  "assets": [],
  "pagination": {
    "page": 1,
    "pageSize": 6,
    "totalCount": 0,
    "totalPages": 0
  }
}
```

Page numbers start at one. An omitted page defaults to page one. The backend sets the page size to `pagination.DefaultPageSize` and does not accept an arbitrary browser-supplied page size.

Supported filters and sorting are defined by `model.AssetListQuery`. Sort fields, sort directions, vulnerability-count modes, and numeric values are validated and allowlisted by the asset service before reaching the repository.

`GET /api/assets/summary` remains separate from the paged table response. It provides dashboard totals for the authenticated user and is not limited to the six displayed rows.

## 🔄 Workflow

1. Angular requests an asset page with `page` and any active filters or sort options.
2. The asset controller binds the query and passes it to the service.
3. The asset service applies the page-size policy, trims and validates input, and applies safe defaults.
4. The repository scopes the query to the authenticated user, applies filters and sorting, counts the matching rows, then applies the offset and limit.
5. If a requested page is beyond the final page, the service normalizes it to the last available page and loads that page.
6. The controller maps the page into `{ assets, pagination }`.
7. Angular renders the returned rows and metadata through the shared `PaginationComponent`.

When a filter or sort changes, the asset screen returns to page one before loading again. Loading, empty, error, first-page, and final-page states are handled without offering invalid navigation.

## 🧩 Architecture and Boundaries

```text
Angular AssetsPage
        |
        v
asset controller -> asset service -> asset repository -> PostgreSQL
        |                 |                 |
        |                 |                 -> scoped count, order, offset, limit
        |                 -> validation and page policy
        -> binding and response mapping
```

- `api/common/pagination` owns the small shared request, page, metadata, and validation types.
- `api/model/asset.go` owns asset-specific list filters and sort vocabulary.
- The controller owns HTTP binding and DTO mapping; it does not implement pagination rules.
- The service owns normalization, validation, page-size policy, and out-of-range page handling.
- The repository owns database filtering, counting, ordering, and bounded retrieval.
- `ui/src/app/components/pagination` owns the reusable accessible controls.
- Relationship pages keep their contextual asset or vulnerability rows together and currently use a one-page footer; their attach-candidate lists are intentionally not paged.

## 🛡️ Security and Invariants

- Every asset page is scoped to the authenticated user on the server.
- A page number never bypasses ownership or authorization checks.
- Search text is escaped before it is used in database pattern matching.
- Sort fields and directions are allowlisted before they are converted into SQL ordering.
- Ordering includes `assets.id ASC` as a deterministic tie-breaker, so rows do not move unpredictably between pages when primary sort values match.
- Total counts describe the filtered result set, not the current page.
- Pagination controls are a usability feature; the backend remains the authority for access and data boundaries.

## 🧪 Verification

The backend tests cover request validation, page-count boundaries, metadata, query ordering, filtering, ownership, and out-of-range page normalization. Angular tests cover the shared pagination component and page interaction behavior. Focused checks should be run from `BlackRadar/` for Go and `BlackRadar/ui/` for Angular.

## 🚧 Current Limitations

- The main vulnerability list still loads through its existing unpaged API contract.
- Asset page size is fixed at six rows; user-selectable page sizes are not implemented.
- Relationship tables have a one-page presentation rather than independent server-side pagination.
- Future vulnerability pagination should reuse the same contract only after its filtering, ownership, and total-count behavior are defined and tested.

## 🔑 Key Terms

- **Page:** One bounded set of rows returned for a list request.
- **Page size:** The maximum number of rows in a page; currently six for assets.
- **Total count:** The number of rows matching the active filters before pagination.
- **Total pages:** The number of pages required for the filtered result set.
- **Server-side pagination:** Filtering, counting, and row selection performed by the backend and database.
- **Relationship page:** A contextual list of vulnerabilities attached to an asset or assets affected by a vulnerability.
