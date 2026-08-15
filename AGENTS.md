# AGENTS.md

This file is the repository entry point for Codex. Keep it short and safe to keep in git.

## Read first

Before editing files, read:

- this file
- `README.md`
- the relevant skill files in `.agents/skills/`
- the source files and tests in the area you are changing

Use the skills as the source of truth for:

- clean code and file structure
- architecture and boundaries
- security and trust boundaries
- roadmap and planned work
- document writing
- Git branch, commit, push, and cleanup workflows

## Repository skills

- `architecture`: current BlackRadar component boundaries, layering, and ownership rules
- `clean-code`: naming, structure, and small-change implementation conventions
- `docs-writing`: README, AGENTS, and `BlackRadar/docs/` writing guidance
- `git-operations`: safe branch switching, commit, push, and cleanup commands for this checkout
- `roadmap`: planned work, future features, and what belongs in current-vs-future docs
- `security`: security boundaries, authorization, session, and trust rules for this repo

## Repo layout

- The outer repository root is the workspace root.
- `BlackRadar/` is the active application root.
- Run Go commands from `BlackRadar/`.
- Run Angular/UI commands from `BlackRadar/ui/`.
- Run Docker Compose from the repository root.

## Working rules

- Inspect the smallest relevant slice of code first.
- Make small, safe changes.
- Keep current behavior and planned behavior separate.
- Follow nearby patterns unless they are clearly wrong.
- Explain the plan before any non-trivial or broad change.
- Verify the exact path you are changing with tests or the smallest useful check.

## Verification scope

- Run focused tests for the changed package, feature, or component rather than the entire test suite.
- Codex runs only focused local unit tests for changed code; the user runs Docker-based integration and environment tests.
- Do not create or manage custom local Go cache directories for verification; use the repository's normal test command or the user's Docker workflow.
- Run the full backend or frontend suite only when the change crosses package boundaries, affects shared infrastructure, authentication, authorization, migrations, or security, or the user explicitly requests it.
- For minor frontend layout, styling, or copy changes, do not run a production build unless the change affects template compilation, shared configuration, or the user explicitly requests it.
- Use the smallest relevant formatter, static check, and test command from the active application root: `BlackRadar/` for Go and `BlackRadar/ui/` for Angular.

## Safety rules

- Do not change public APIs, database schema, authentication, authorization, dependencies, Docker, CI/CD, or deployment behavior without explicit approval.
- Do not edit generated files, build output, caches, logs, or dependency trees unless the task requires it.
- Do not expose secrets, tokens, credentials, or other sensitive values in code, docs, logs, or chat.
- Do not weaken security controls, trust browser-provided ownership data, or move authorization into the wrong layer.
- Do not broaden scope silently; stop and ask if the change needs to expand.

## What to prefer

- Current code and tests over memory.
- Small feature-scoped edits over broad refactors.
- Explicit names and narrow interfaces.
- Repository-local examples over invented patterns.
- Security, architecture, clean code, and roadmap guidance from the matching skill file instead of duplicating it here.
