# ⚙️ GitHub Actions CI

## Overview

BlackRadar currently uses GitHub Actions for pull-request and `master` branch validation. The workflow checks backend and frontend changes, runs dependency security checks, builds the application, and creates short-lived artifacts. It does not deploy the application.

## Purpose

The pipeline gives each change the same basic checks before it is merged:

- Go formatting and static analysis
- Backend and frontend lint and tests
- Go and Angular dependency security scanning
- Trivy filesystem and backend-container scanning for high and critical vulnerabilities, secrets, and misconfigurations
- Backend and frontend build artifacts plus a backend container build

The workflow is intentionally separate from Docker Compose. Compose remains the local development runtime and is not required for every CI run.

For normal changes, create a feature branch and open a pull request into `master` so the checks and review requirements can run before merging.

## Current workflow

The workflow is defined in `.github/workflows/ci.yml` and runs when:

- a pull request targets `master`
- a change is pushed to `master`
- a maintainer starts a manual `workflow_dispatch` run

Older runs for the same workflow reference are cancelled when a newer run starts. Each job declares its own permissions: all jobs have `contents: read`, while only the `security` and `build` jobs have the narrowly scoped `security-events: write` permission needed to publish Trivy SARIF findings to GitHub Code Scanning. The workflow does not use repository secrets.

The workflow uses third-party actions pinned to immutable commit SHAs. Dependabot checks those action references monthly and opens pull requests for updates through `.github/dependabot.yml`.

## CI jobs

### Format and static checks

This job runs from `BlackRadar/` and:

1. Checks out the repository with a pinned action.
2. Installs the Go version declared in `BlackRadar/go.mod`.
3. Fails if `gofmt` reports unformatted Go files.
4. Runs `go vet ./...`.

The frontend lint step runs the repository's existing Prettier dependency against
TypeScript, HTML, CSS, and SCSS source files. It is a formatting/static check;
an ESLint-based Angular lint target remains future work.

The `format-lint` job runs this frontend check alongside Go formatting and
static analysis.

### Testing

The testing job runs both test suites:

- `go test ./...` from `BlackRadar/`
- `npx --no-install ng test --watch=false` from `BlackRadar/ui/`

### Security scan

The security job installs the pinned `govulncheck` tool into the temporary GitHub runner directory and scans the backend with:

```text
govulncheck ./...
```

The scanner is not added to the application’s Go dependencies. The same job runs:

```text
npm audit --audit-level=high
```

against the frontend lockfile.

The frontend keeps Angular on its current major version. Its `package.json` uses
narrow npm `overrides` for patched transitive versions of `undici`,
`@hono/node-server`, `@modelcontextprotocol/sdk`, and `fast-uri`; the lockfile
is regenerated and verified with `npm ci` and `npm audit --audit-level=high`.

The security job also scans the checked-out repository with Trivy for high and
critical vulnerabilities, secrets, and misconfigurations. The build job scans
the backend container immediately after building it, using the same thresholds.
Medium findings are scanned separately and uploaded as advisory SARIF results
only for trusted `push` and `workflow_dispatch` runs; pull-request runs do not
upload SARIF. They do not fail the workflow. Both Trivy and SARIF upload action
references are pinned to immutable commit SHAs.

### Dependency maintenance

Dependabot is configured in `.github/dependabot.yml` with monthly checks for:

- Go modules in `BlackRadar/`
- npm packages in `BlackRadar/ui/`
- the Dockerfile in `BlackRadar/`
- GitHub Actions in `.github/workflows/`

Dependabot creates pull requests; the existing CI workflow validates those pull
requests before they are merged. CI does not run `npm audit fix` automatically,
especially when the proposed fix would cross an Angular major version.

### Build and container

This job runs only after the format, testing, and security jobs succeed. It:

- builds the backend binary
- builds the Angular production output
- builds the backend Docker image locally
- uploads the backend and frontend artifacts

The container is tagged with the commit SHA and is not pushed to a registry.

## Build artifacts

The job creates:

- `blackradar-backend-<commit-sha>`: the compiled Go backend binary
- `blackradar-frontend-<commit-sha>`: the Angular production output

Artifacts are retained for seven days. The artifact paths are created in the runner’s temporary directory and do not include `.env` files, credentials, tokens, logs, caches, or dependency directories.

## Security boundaries

- Each job has `contents: read`; `security-events: write` is limited to the `security` and `build` jobs for publishing Trivy SARIF results.
- Third-party actions are pinned to immutable commit SHAs.
- Pull-request validation does not require secrets.
- CI does not print environment variables or credentials.
- `npm audit fix` is not run automatically.
- CI does not start Docker Compose or require local database credentials.
- CI builds the backend container but does not deploy or publish images.

## Rerunning a failed workflow

Open the failed workflow run in GitHub, inspect the failed job and step, and use **Re-run failed jobs** after correcting the cause. A manual run can also be started from the workflow’s **Run workflow** menu.

## Required checks before merging

The default branch should require these checks after the workflow is available in GitHub:

- Format and static checks
- Testing
- Security scan
- Build and container

Review requirements and conversation resolution should also be enabled through GitHub branch protection.

## Current limitations and future work

The current pipeline does not provide a deployment workflow, container registry publishing, cloud authentication, or a protected release environment. When a deployment target is selected, deployment should use a protected GitHub environment, environment-scoped secrets, and OIDC authentication where supported.

The frontend has no lint target yet, and Prettier validation remains deferred until the existing formatting baseline is intentionally cleaned up. The backend container build may later be extended into a release workflow, but it must remain separate from deployment approval and image publishing.

An ESLint-based Angular lint target remains future work. The backend container build may later be extended into a release workflow, but it must remain separate from deployment approval and image publishing.

## Key Terms

- **CI:** Automated checks that validate a change.
- **Artifact:** A build output stored by GitHub Actions for later inspection or release use.
- **Protected environment:** A GitHub environment that can require reviewers and scope deployment secrets.
- **OIDC:** Short-lived identity federation used by CI to authenticate to a deployment provider without storing long-lived cloud keys.
