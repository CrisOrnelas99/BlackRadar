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
