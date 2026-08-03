# ⚙️ GitHub Actions CI

## Overview

BlackRadar currently uses GitHub Actions for pull-request and `master` branch validation. The workflow checks backend and frontend changes, runs dependency security checks, and creates short-lived build artifacts. It does not deploy the application.

## Purpose

The pipeline gives each change the same basic checks before it is merged:

- Go formatting, static analysis, and tests
- Go dependency vulnerability scanning
- Angular dependency auditing, tests, and production build validation
- Backend and frontend build artifacts for inspection

The workflow is intentionally separate from Docker Compose. Compose remains the local development runtime and is not required for every CI run.

## Current workflow

The workflow is defined in `.github/workflows/ci.yml` and runs when:

- a pull request targets `master`
- a change is pushed to `master`
- a maintainer starts a manual `workflow_dispatch` run

Older runs for the same workflow reference are cancelled when a newer run starts. The workflow has `contents: read` permissions and does not use repository secrets.

## Validation jobs

### Backend validation

The backend job runs from `BlackRadar/` and:

1. Checks out the repository with a pinned action.
2. Installs the Go version declared in `BlackRadar/go.mod`.
3. Fails if `gofmt` reports unformatted Go files.
4. Runs `go vet ./...`.
5. Runs `go test ./...`.

### Go dependency security

The Go security job installs the pinned `govulncheck` tool into the temporary GitHub runner directory and scans the backend with:

```text
govulncheck ./...
```

The scanner is not added to the application’s Go dependencies.

### Frontend validation

The frontend job runs from `BlackRadar/ui/` and:

1. Uses Node 22, matching the current frontend Docker development image.
2. Installs exactly from `package-lock.json` with `npm ci`.
3. Runs `npm audit --audit-level=high`.
4. Runs Angular tests without watch mode.
5. Runs the production Angular build.

The repository currently has no Angular lint target. Prettier validation is deferred until the existing frontend formatting baseline is intentionally reviewed and cleaned up.

## Build artifacts

The build job runs only after backend validation, Go security scanning, and frontend validation succeed. It creates:

- `blackradar-backend-<commit-sha>`: the compiled Go backend binary
- `blackradar-frontend-<commit-sha>`: the Angular production output

Artifacts are retained for seven days. The artifact paths are created in the runner’s temporary directory and do not include `.env` files, credentials, tokens, logs, caches, or dependency directories.

## Security boundaries

- Workflow repository permissions are read-only.
- Third-party actions are pinned to immutable commit SHAs.
- Pull-request validation does not require secrets.
- CI does not print environment variables or credentials.
- `npm audit fix` is not run automatically.
- CI does not start Docker Compose or require local database credentials.
- CI does not deploy or publish images.

## Rerunning a failed workflow

Open the failed workflow run in GitHub, inspect the failed job and step, and use **Re-run failed jobs** after correcting the cause. A manual run can also be started from the workflow’s **Run workflow** menu.

## Required checks before merging

The default branch should require these checks after the workflow is available in GitHub:

- Backend validation
- Go dependency security
- Frontend validation
- Build artifacts

Review requirements and conversation resolution should also be enabled through GitHub branch protection.

## Current limitations and future work

The current pipeline does not provide a deployment workflow, container registry publishing, cloud authentication, or a protected release environment. When a deployment target is selected, deployment should use a protected GitHub environment, environment-scoped secrets, and OIDC authentication where supported.

Docker image validation may be added later if container release checks become necessary. It should remain separate from ordinary source validation and must not push or deploy images without an explicitly configured release process.

## Key Terms

- **CI:** Automated checks that validate a change.
- **Artifact:** A build output stored by GitHub Actions for later inspection or release use.
- **Protected environment:** A GitHub environment that can require reviewers and scope deployment secrets.
- **OIDC:** Short-lived identity federation used by CI to authenticate to a deployment provider without storing long-lived cloud keys.
