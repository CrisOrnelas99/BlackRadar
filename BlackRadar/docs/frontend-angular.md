# 🖥️ Frontend Angular

## 🧭 Overview

The frontend is an Angular SSR application under `BlackRadar/ui`. It provides navigation, forms, session presentation, API calls, and user feedback. It is not a security authority.

## 🧱 Structure

The application is organized around Angular configuration, routes, components, services, and shared styling. Browser and server route configuration must remain aligned because the application supports SSR.

The frontend communicates with the Go backend through feature API services. NVD, OpenAI, database, ownership, authorization, and risk decisions remain server-side.

## 🔐 Authentication UX

The UI keeps the current session presentation in memory, attaches access tokens to API requests, and attempts one cookie-backed refresh after an unauthorized response. A failed refresh clears the session and returns the user to login.

Route guards redirect unauthenticated users for usability. A guarded page is not a protected resource; every backend route must independently enforce authentication and authorization.

## 🧭 Current Screens

The current application includes authentication, a protected dashboard, asset and vulnerability lists, detail pages, attached-vulnerability and affected-asset relationship pages, and the approved CPE scan workflow. The asset inventory uses the shared `PaginationComponent` with backend page metadata; filters and sorting return the view to page one. Relationship counts and attached-vulnerability results refresh from backend responses after a successful scan. Vulnerability details show NVD's publication timestamp when the imported CVE provides one.

Frontend models should follow the backend response contract. UUID-backed identifiers and nullable risk fields must not be represented as incompatible numeric or mandatory values.

## 🛡️ Browser Boundary

The browser must not:

- calculate authoritative risk
- set ownership, role, user ID, or organization scope
- call NVD or OpenAI directly
- treat route guards as authorization
- display raw backend or provider errors

See [security-boundaries.md](security-boundaries.md), [users-auth-sessions.md](users-auth-sessions.md), and [api-error-handling.md](api-error-handling.md) for shared rules.

Asset pagination details, including the backend and UI boundaries, are documented in [pagination.md](pagination.md).

## 🎭 Walkthrough: Protected Navigation

1. Alice has a valid session; Bob is not authenticated.
2. Alice opens a protected asset page while Bob is redirected to login.
3. Angular evaluates navigation before rendering the protected screen.
4. Route guards and auth services handle the UI flow; the backend middleware still authorizes every API request.
5. The guard improves navigation, but only the server can protect data and actions.
6. The frontend attaches the in-memory access token through its API pipeline, refreshes through the HttpOnly refresh cookie when needed, clears session state as appropriate, and renders server results without making authorization decisions itself.

## 🔑 Key Terms

- **SSR:** Server-side rendering of Angular routes before browser hydration.
- **Interceptor:** A client-side request pipeline used here for authentication headers and refresh behavior.
- **Route guard:** A navigation check intended for UX, not backend security.
- **Protected page:** A UI route that should be available only to an authenticated user, subject to backend enforcement.
