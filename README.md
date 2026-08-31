# Trustify Dependency Analytics GitHub Action

Analyze dependencies for vulnerabilities and license conflicts using Trustify.

## Features

This action supports three operation modes:

- **remediate**: Automatically creates PRs with dependency updates to fix vulnerabilities
- **check**: Analyzes dependencies and reports findings without creating PRs
- **sbom**: Generates and uploads Software Bill of Materials (SBOM)

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
    sources: pom.xml,package.json
```

### Check Mode

Analyze dependencies and fail the build on high-severity findings:

```yaml
- name: Check Dependencies
  uses: trustification/trustify-da-action@v1
  with:
    mode: check
    backend-url: https://trustify.example.com
    group-by: severity
```

### SBOM Mode

Generate and upload SBOM artifacts:

```yaml
- name: Generate SBOM
  uses: trustification/trustify-da-action@v1
  with:
    mode: sbom
    sbom-targets: artifact,oci
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `mode` | Operation mode: `remediate`, `check`, or `sbom` | Yes | - |
| `backend-url` | Trustify backend URL | No | - |
| `providers` | Comma-separated list of vulnerability providers | No | - |
| `sources` | Comma-separated list of manifest paths to analyze | No | Auto-detect |
| `group-by` | Grouping strategy: `package`, `severity`, or `file` | No | `package` |
| `dry-run` | Preview changes without creating PRs (remediate mode) | No | `false` |
| `sbom-targets` | Upload targets: `artifact`, `oci` (sbom mode) | No | `artifact` |
| `config-path` | Path to `.trustify-da.yml` config file | No | `.trustify-da.yml` |

## Outputs

| Output | Description | Modes |
|--------|-------------|-------|
| `remediation-count` | Number of vulnerabilities remediated | remediate |
| `critical-count` | Number of critical vulnerabilities found | all |
| `high-count` | Number of high severity vulnerabilities found | all |
| `medium-count` | Number of medium severity vulnerabilities found | all |
| `low-count` | Number of low severity vulnerabilities found | all |
| `license-conflicts` | Number of license policy conflicts detected | check, remediate |
| `pr-url` | URL of created/updated PR | remediate |
| `sbom-path` | Path to generated SBOM | sbom |
| `changed-files` | Comma-separated list of files modified | remediate |

## Configuration File

You can provide a `.trustify-da.yml` file in your repository:

```yaml
backendUrl: https://trustify.example.com
providers:
  - osv
  - snyk
groupBy: severity
sources:
  - pom.xml
  - package.json
```

Action inputs override config file values.

## License

Apache-2.0
