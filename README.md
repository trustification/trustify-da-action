# Trustify Dependency Analytics GitHub Action

Analyze dependencies for vulnerabilities and license conflicts using Trustify.

## Features

This action supports three operation modes:

- **remediate**: Automatically creates PRs with dependency updates to fix vulnerabilities
- **check**: Analyzes dependencies and reports findings as a step summary with structured outputs for policy gates
- **sbom**: Generates a Software Bill of Materials (SBOM)

## Usage

### Remediate Mode

Automatically create PRs to fix vulnerable dependencies:

```yaml
- name: Remediate Vulnerabilities
  uses: trustification/trustify-da-action@v1
  with:
    mode: remediate
    backend-url: https://trustify.example.com
    providers: osv,snyk
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Requires `contents: write` and `pull-requests: write` permissions.

### Check Mode

Analyze dependencies, report findings, and optionally fail the build:

```yaml
- name: Check Dependencies
  uses: trustification/trustify-da-action@v1
  with:
    mode: check
    backend-url: https://trustify.example.com
    fail-on-critical: true
    fail-on-high: 5
```

Requires `contents: read` permission.

### SBOM Mode

Generate a CycloneDX SBOM from discovered manifests:

```yaml
- name: Generate SBOM
  id: sbom
  uses: trustification/trustify-da-action@v1
  with:
    mode: sbom

- name: Upload SBOM artifact
  if: steps.sbom.outputs.sbom-path != ''
  uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: ${{ steps.sbom.outputs.sbom-path }}
```

Requires `contents: read` permission. No backend URL is needed, SBOM generation does not call the Trustify backend, though underlying package managers may make outbound network calls to resolve dependency metadata. The `sbom-path` output points to a directory containing one `.cdx.json` file per manifest, which downstream steps can upload, sign, or push to a registry.

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `mode` | Operation mode: `remediate`, `check`, or `sbom` | Yes | - |
| `backend-url` | Trustify backend URL (also settable via `.trustify-da.yml` or `TRUSTIFY_DA_BACKEND_URL` env var) | Yes | - |
| `providers` | Comma-separated list of vulnerability providers | No | - |
| `group-by` | Grouping strategy for remediation PRs: `dependency` or `bundle` | No | `dependency` |
| `dry-run` | Preview changes without creating PRs (remediate mode) | No | `false` |
| `labels` | Comma-separated labels to apply to remediation PRs | No | `trustify-da` |
| `branch-prefix` | Branch name prefix for remediation PRs | No | `trustify-da` |
| `fail-on-critical` | Fail when critical vulnerabilities meet or exceed this threshold (check mode). `true` or `0` to fail on any; `false` or omit to disable. | No | - |
| `fail-on-high` | Fail when high vulnerabilities meet or exceed this threshold (check mode). `true` or `0` to fail on any; `false` or omit to disable. | No | - |
| `fail-on-license-conflicts` | Fail when license conflicts meet or exceed this threshold (check mode). `true` or `0` to fail on any; `false` or omit to disable. | No | - |

## Outputs

| Output | Description | Modes |
|--------|-------------|-------|
| `remediation-count` | Number of vulnerabilities remediated or with an available fix | remediate, check |
| `critical-count` | Number of critical vulnerabilities found | check |
| `high-count` | Number of high severity vulnerabilities found | check |
| `medium-count` | Number of medium severity vulnerabilities found | check |
| `low-count` | Number of low severity vulnerabilities found | check |
| `license-conflicts` | Number of license policy conflicts detected | check |
| `pr-url` | URL of created/updated PR(s) | remediate |
| `sbom-path` | Path to generated SBOM | sbom |
| `changed-files` | Comma-separated list of files modified | remediate |

## Permissions

| Mode | Required Permissions |
|------|---------------------|
| `check` | `contents: read` |
| `remediate` | `contents: write`, `pull-requests: write` |
| `sbom` | `contents: read` |

Remediate mode also requires `GITHUB_TOKEN` to be available (via the `env` key or the repository's default token).

## Configuration File

You can provide a `.trustify-da.yml` file in your repository root (or any parent
directory, the action walks up from the workspace to find it):

```yaml
backend-url: https://trustify.example.com
providers:
  - osv
  - snyk
remediation:
  group-by: dependency
  labels:
    - trustify-da
    - security
  branch-prefix: trustify-da
  exclude:
    - "@internal/private-pkg"
check:
  fail-on:
    critical: 0
    high: 5
```

Action inputs override config file values. Environment variables sit between the two:
action input > env var > config file > default.

| Environment Variable | Overrides |
|---------------------|-----------|
| `TRUSTIFY_DA_BACKEND_URL` | `backend-url` |
| `TRUSTIFY_DA_PROVIDERS` | `providers` |
| `TRUSTIFY_DA_GROUP_BY` | `group-by` / `remediation.group-by` |

## License

Apache-2.0
