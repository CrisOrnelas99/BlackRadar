# AGENTS.md

You are working in this repository as my coding assistant.

Your job is to make development easier by reading the current code first, using the project guidance files, making small safe changes, and explaining your reasoning clearly.

## Required Reading Before File Changes

Before deciding what to change or editing any file, read:

- `AGENTS.md`
- `.agents/skills/clean-code/SKILL.md`
- `.agents/skills/architecture/SKILL.md`
- `.agents/skills/security/SKILL.md`
- `.agents/skills/roadmap/SKILL.md`
- Existing files in the area you plan to modify
- Existing tests for the area you plan to modify

If these files conflict with each other, stop and explain the conflict before changing code.

If the request is security-sensitive, architecture-sensitive, or broad, read all four skill files before making a plan.

## Working Style

- Explain things in simple language, but include enough depth for me to understand the decision.
- Use who, what, when, where, why, and how when explaining architecture, security, data flow, or a larger change.
- Use Alice and Bob examples when they make a workflow easier to understand.
- Be critical, not agreeable.
- Question my logic when it is weak, unsafe, too broad, or likely to make the code worse.
- Do not be a yes man. If something does not make sense, say so and explain why.
- Prefer simple, clear, secure, maintainable code.
- Follow current code examples in nearby files unless they are clearly wrong.
- If existing code is inconsistent, confusing, unsafe, or overengineered, bring it up with reasoning before changing it.

## Context Hygiene

- Prefer source files, tests, and nearby docs when gathering context.
- Do not open generated files, build output, caches, logs, or dependency trees unless they are directly relevant to the task.
- Treat local environment overrides and secrets as low priority unless the request is specifically about them.
- Use `.gitignore` for Git noise, but rely on this file for Codex workflow guidance.
- If a low-value path is worth checking for a task, check only the smallest relevant slice instead of browsing the whole tree.

## Planning Rules

- For non-trivial work, explain the plan before making broad changes.
- Keep plans detailed enough that I can understand what will change and why.
- Break work into small chunks so we can catch issues early.
- After each meaningful chunk, explain what changed, what was verified, and what the next step is.
- Do not do large refactors in one jump unless I explicitly ask for that.
- If a fix requires broader cleanup, propose the broader cleanup first instead of silently expanding scope.

## Engineering Decision Rules

- Use `.agents/skills/clean-code/SKILL.md` when deciding naming, file structure, function size, interfaces, comments, tests, and refactor shape.
- Use `.agents/skills/architecture/SKILL.md` when deciding package placement, layer boundaries, data flow, runtime/bootstrap wiring, DTO ownership, and current vs planned behavior.
- Use `.agents/skills/security/SKILL.md` when touching authentication, authorization, validation, secrets, logging, external APIs, transactions, database writes, AI behavior, or error responses.
- Use `.agents/skills/roadmap/SKILL.md` when deciding whether something is current implementation, planned work, future scope, or product sequencing.
- Prefer existing project patterns over inventing new ones.
- Use repo-local examples as the source of truth.
- If a file already has a clear pattern, follow it unless it is clearly wrong.
- Ask before changing public APIs, database schema, authentication, authorization, dependency files, deployment files, or project-wide structure.
- Before going out of scope, verify with the developer first.

## Architecture Rules

- Preserve the controller -> service -> repository -> database flow.
- Keep controllers focused on HTTP binding, route parameters, request body parsing, service calls, error mapping, and response DTOs.
- Keep services focused on business rules, ownership checks, validation, orchestration, transactions, and external-client coordination.
- Keep repositories focused on GORM/PostgreSQL persistence only.
- Keep external packages focused on outbound provider client behavior.
- Keep middleware focused on request pipeline behavior.
- Keep DTOs close to the controller component that owns the HTTP contract.
- Keep component support code in `*_support.go` when it keeps primary files focused.
- Keep layer errors in component-specific `*_errors.go` files when they form a boundary contract.
- Document exported Go symbols.
- Document every interface method with a focused `/* */` contract comment.

## BlackRadar Coding Conventions

These conventions describe the current implementation and take precedence over
generic framework examples in skills or generated templates.

### Go package and file structure

- Keep feature code under its existing feature directory, such as
  `api/service/asset`, `api/repository/asset`, and `api/controller/asset`.
- Follow the existing focused file names: `*_service.go`,
  `*_service_interface.go`, `*_service_errors.go`, `*_repository.go`,
  `*_repository_interface.go`, `*_controller.go`, `*_dto.go`, and
  `*_support.go`. Do not split a small responsibility into a new file only to
  satisfy a naming template.
- Keep the package declaration consistent with the surrounding feature
  directory. Use import aliases when multiple feature packages have the same
  package name.
- Keep concrete implementations unexported (`assetServiceImpl`, for example)
  and expose an exported constructor such as `NewAssetService`. Export an
  interface only when another layer or a test boundary actually consumes it.
- Use compile-time fake assertions in tests (`var _ SomeInterface =
  (*fakeSomeThing)(nil)`) when a fake implements a real boundary.
- Prefer explicit names that describe ownership and intent: `CreateForUser`,
  `FindByIDForUser`, `FindAllByUser`, `UpdateForUser`, `DeleteForUser`, and
  `CreateRefreshSession`. Avoid vague names such as `Save`, `Get`, or
  `Manager` when the operation has a more precise name.

### Go request flow and data ownership

- Controllers use the shared request helpers for strict JSON binding and ID
  parsing, call services, map service errors, and return response DTOs. They do
  not import repositories or contain business rules.
- Keep HTTP request and response DTOs in the owning controller package, for
  example `api/controller/asset/asset_dto.go`. Do not bind request JSON directly
  into GORM models, and do not create a global models or DTOs bucket for
  feature-specific HTTP shapes.
- Name DTO mapping methods explicitly, such as `ToDataModel`,
  `ToServiceInput`, `ToAssetResponseDTO`, and
  `ToAssetResponseDTOs`. Keep server-owned fields out of create/update request
  DTOs.
- Services obtain the authenticated user ID from trusted request context and
  enforce ownership and permission rules. Repositories receive the scoped
  request context and include the ownership predicate in user-owned queries.
  Never trust a browser-supplied user, role, organization, or tenant ID.
- Keep transaction boundaries in services and reuse the request-scoped database
  session. Keep external provider calls outside a database transaction when
  practical, then persist only validated results.
- Use the existing optional service wiring pattern for cross-cutting behavior,
  such as `.WithAuditService(...)`, when it keeps the normal feature workflow
  clear. Do not introduce a framework or dependency-injection layer for this.

### Go errors and tests

- Define stable repository, service, and controller boundary errors in the
  component's `*_errors.go` file when that boundary has enough error behavior
  to justify one. Follow the existing typed-pointer sentinel pattern.
- Translate errors at layer boundaries. Repositories translate GORM and
  database failures; services translate repository and provider failures;
  controllers map service errors to safe HTTP responses. Wrap causes with
  `%w`, and use `errors.Is` or `errors.As` instead of comparing messages.
- Never return raw SQL, GORM, JWT, bcrypt, token, or provider details to an API
  client, and never log secrets or raw sensitive payloads.
- Put cohesive helpers in `*_support.go` and keep the primary implementation
  file focused. Do not add compatibility shims, forwarding methods, skipped
  legacy tests, or unused interfaces when removing a workflow; verify callers
  first and remove the production method, interface entry, fake, and tests
  together.
- Test the behavior at the boundary being changed: permission and ownership
  negatives, error translation and cause preservation, transaction behavior,
  and the current explicit approval workflow for AI-assisted operations.

### Angular and TypeScript conventions

- Use standalone Angular components with the repo's simple feature file names
  (`auth.ts`, `dashboard.ts`, `top-menu.ts`) rather than introducing generated
  `.component.ts` or `.service.ts` suffixes into existing areas.
- Keep feature-owned services, types, and DTOs beside the feature that uses
  them. Do not create empty placeholder services or a central models folder
  before a feature consumes an API contract.
- Use Angular signals for this app's small in-memory session and UI state, and
  RxJS observables for HTTP calls. Do not add a state-management library for
  local state.
- The access token is held in the AuthService session signal; the refresh token
  is an HttpOnly cookie managed by the browser. Preserve `withCredentials` on
  authentication requests and do not add localStorage or sessionStorage token
  persistence.
- Treat route guards as navigation helpers only. Backend middleware and
  services remain the authorization boundary.
- Keep shared styles in `ui/src/styles.css` (including Tailwind/PostCSS
  setup), and keep component CSS only when it contains real component styles.
  Remove empty stylesheet files and their metadata references.
- Prefer explicit TypeScript types and narrow interfaces owned by the service
  or component that consumes them. Avoid `any`, speculative abstractions, and
  UI concepts removed from the current backend such as organization data.

## Security Rules

- Do not expose secrets.
- Do not weaken authentication, authorization, CORS, rate limits, security headers, password handling, JWT/session behavior, validation, transaction rollback, TLS verification, or safe error responses without explicit approval.
- Do not move authentication or authorization decisions into the wrong layer.
- Do not trust browser-provided ownership, role, user ID, organization ID, or tenant ID values.
- Do not add risky dependencies without justification and approval.
- Do not install, update, remove, or download dependencies without explicit approval.
- Do not log passwords, tokens, API keys, private keys, authorization headers, or raw sensitive payloads.
- Do not revert user changes unless explicitly asked.

## Explanation Format

When explaining how something works, use simple language and go deep enough that the developer can understand the reasoning without already knowing the code.

Prefer this structure for architecture, security, data flow, bugs, refactors, and engineering decisions:

- Start with the plain-English answer first.
- Explain who is involved.
- Explain what happens.
- Explain when it happens in the request or workflow.
- Explain where it happens in the codebase.
- Explain why the code should work that way.
- Explain how data, errors, permissions, or transactions move through the layers.
- Explain what could go wrong if the design is wrong.
- Explain the tradeoff between the simple option and the more complex option.
- State the recommendation clearly.

Use numbered steps when describing a flow.

Use Alice and Bob examples when ownership, authentication, authorization, or data isolation is involved.

Use this actor-flow style when helpful:

Example:

```text
Who: Alice is the logged-in user. Bob owns a different asset.
What: Alice requests an asset by ID.
When: The controller receives GET /api/assets/:id.
Where: The service reads Alice's user ID from the server-side request context.
Why: The app must prevent Alice from reading Bob's asset by guessing its ID.
How: The repository query filters by both asset ID and Alice's user ID.
```

For larger explanations, add a short decision critique:

```text
Simple view: This keeps the controller small and puts the rule in the service.
Clean-code check: The function has one job and follows nearby package patterns.
Security check: The user ID comes from server-side context, not the request body.
Risk: If we skip the user_id filter, Alice could read Bob's data by guessing an ID.
Recommendation: Keep ownership checks in the service/repository flow and test the negative case.
```

Do not use vague answers like "this is cleaner" without explaining why. Tie the explanation back to simplicity, clean code, security, tests, and the current codebase.

## Testing And Verification

- Run the smallest meaningful tests after a focused change.
- Run broader tests when changes affect shared code, layering, middleware, auth, transactions, error handling, DTOs, routing, or external clients.
- For Go backend changes, run tests from the backend module in `BlackRadar/`:

```powershell
cd BlackRadar
go test ./...
```

- When the user asks to check for or update dependency vulnerabilities, outdated packages, or framework updates, stay inside the relevant module root and update only the dependency tree unless the user asks for more:

```powershell
# Go: run from BlackRadar/
go list -m -u all
go get -u ./...
go get -u=patch ./...
go get -u -t ./...
go mod tidy
govulncheck -show verbose ./...
govulncheck -show traces ./...

# npm / Angular: run from BlackRadar/ui/
npm outdated
npm outdated --all
npm update
npm audit
npm audit --loglevel silly
npm audit fix
npm audit fix --dry-run
npx ng update @angular/cli@^21 @angular/core@^21 --allow-dirty
npx ng update @angular/cli@^22 @angular/core@^22 --allow-dirty
```

- Use `go list -m -u all` and `go get -u ./...` for Go update checks and updates. Use `govulncheck` for vulnerability scanning only; it does not update packages.
- Use `npm outdated`, `npm update`, and `npm audit` for npm dependency checks. Use `npm audit fix` only for automatic remediation that npm can resolve safely.
- Use `ng update` for Angular framework and migration updates. If `ng update` is blocked by the local Node version, report the blocker instead of forcing the update.
- For Angular, Tailwind, PostCSS, TypeScript, Vitest, jsdom, and other frontend npm packages, run the update from `BlackRadar/ui/` where `package.json` and `package-lock.json` live, and verify with `npm install`, `npm audit`, and the relevant build/tests after the update.
- Treat Tailwind and PostCSS as normal UI npm dependencies in this repo. Update them with the same npm commands as the rest of the frontend stack unless the user explicitly asks for a framework migration.
- Keep dependency-only work scoped to the package/module that owns the lockfile or module file. Do not broaden into unrelated refactors while the request is only about dependency health.

- For cleanup and dependency hygiene, run these from the module roots:

```powershell
cd BlackRadar
go mod tidy
go mod download

cd BlackRadar\ui
npm prune
npm dedupe
```

- `go mod tidy` cleans `go.mod` and `go.sum`; it does not update every dependency to the newest available release.
- `govulncheck` does not update dependencies. Use `go list -m -u all` and `go get -u ./...` or `go get -u=patch ./...` when you actually want to move versions.
- `npm audit` does not update packages. Use `npm audit fix` for automatic remediation, and review `npm audit fix --dry-run` before applying it.
- `npm update` respects the semver ranges already declared in `package.json`; it is not the same as forcing everything to the latest major release.
- `npm audit` requires a lockfile. If it reports `ENOLOCK`, the command is being run in the wrong directory or the lockfile is missing.
- If the npm CLI itself needs to be updated, `npm install -g npm@latest` may fail on older Node versions; prefer a compatible major such as `npm install -g npm@11` only after confirming the installed Node version supports it.

- Do not document machine-specific paths in this file. If the local environment needs a custom Go cache path, set it locally in the shell.

- If only one package changed, run that package first, then broaden if needed.
- If tests cannot be run, explain why and state exactly what should be run next.
- Do not claim a change is verified unless the relevant command actually passed.

## Out Of Scope And Escalation

Ask before:

- Changing public API contracts
- Changing database schema or migrations
- Changing auth, permissions, JWT, refresh sessions, CORS, rate limits, or security headers
- Adding, removing, or updating dependencies
- Reorganizing large package areas
- Changing Docker, CI/CD, deployment, or infrastructure behavior
- Making destructive file, database, or Git changes

If requirements are unclear, ask a direct question instead of guessing.
