import * as core from '@actions/core';
import { relative } from 'node:path';
import daClient from '@trustify-da/trustify-da-javascript-client/dist/src/index.js';
import { findManifests } from '@trustify-da/trustify-da-javascript-client/dist/src/remediate.js';
import {
  extractRemediations,
  type Remediation,
} from '@trustify-da/trustify-da-javascript-client/dist/src/remediation.js';
import {
  licensesFromReport,
  getCompatibility,
  getProjectLicense,
} from '@trustify-da/trustify-da-javascript-client/dist/src/license/index.js';
import type { ActionConfig } from '../config.js';
// The DA report types come from the api-model package (a direct devDependency).
// They are imported type-only: esbuild erases them before module resolution, so
// the package's raw-TypeScript source is never pulled into the runtime bundle.
import type { AnalysisReport } from '@trustify-da/trustify-da-api-model/model/v5/AnalysisReport.js';
import type { Source } from '@trustify-da/trustify-da-api-model/model/v5/Source.js';
import type { Scanned } from '@trustify-da/trustify-da-api-model/model/v5/Scanned.js';

/** Vulnerability counts by severity. */
interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/**
 * One row of the per-source vulnerability table: which manifest/provider/source
 * it came from and the severity breakdown for that source.
 */
interface VulnerabilityRow extends SeverityCounts {
  manifest: string;
  provider: string;
  source: string;
}

/** A dependency whose license is incompatible with the project's license. */
interface LicenseConflict {
  purl: string;
  licenses: string[];
  reason: string;
}

/**
 * Aggregated result of analyzing every discovered manifest. Counts are summed
 * across all manifests, providers, and sources.
 */
interface CheckResult {
  scanned: Required<Scanned>;
  severity: SeverityCounts;
  vulnerabilityRows: VulnerabilityRow[];
  remediations: Remediation[];
  remediationCount: number;
  licenseCategoryCounts: Map<string, number>;
  licenseConflicts: LicenseConflict[];
  hasLicenseData: boolean;
}

/**
 * Runs the check mode: analyzes every discovered manifest via the DA backend,
 * writes a detailed markdown summary to `$GITHUB_STEP_SUMMARY`, and sets
 * structured outputs (severity counts, remediation count, license conflicts)
 * that downstream workflow steps can use for policy gates. Check mode never
 * fails the build on findings — policy enforcement is left to the caller; a
 * non-zero exit means the action itself failed.
 */
export async function runCheckMode(config: ActionConfig): Promise<void> {
  core.info('Running in check mode');

  const backendUrl = config.backendUrl || process.env.TRUSTIFY_DA_BACKEND_URL;
  if (!backendUrl) {
    throw new Error(
      'A Trustify DA backend URL is required for check mode. Set it via the backend-url input, the backendUrl config, or the TRUSTIFY_DA_BACKEND_URL env var.'
    );
  }
  // The JS client resolves the backend from this env var; thread the action's
  // input through so every analysis call reaches the backend.
  process.env.TRUSTIFY_DA_BACKEND_URL = backendUrl;

  const workspacePath = process.env.GITHUB_WORKSPACE || process.cwd();

  // A single code path handles zero manifests too: the loop simply doesn't run,
  // leaving a zeroed result that still yields a summary and (importantly) sets
  // every output to 0 so downstream policy gates never see an empty value.
  const manifests = findManifests(workspacePath);
  core.info(
    manifests.length === 0
      ? 'No supported manifests found.'
      : `Analyzing ${manifests.length} manifest(s)...`
  );

  const opts = buildAnalysisOptions(config, backendUrl);
  const result = emptyResult();

  for (const manifest of manifests) {
    const relPath = relative(workspacePath, manifest) || manifest;
    core.info(`Scanning ${relPath}`);

    let report: AnalysisReport;
    try {
      report = await daClient.stackAnalysis(manifest, false, opts);
    } catch (error) {
      throw new Error(
        `Analysis failed for ${relPath}: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    aggregateReport(result, report, relPath, config, manifest);
  }

  writeSummary(
    result,
    manifests.map((m) => relative(workspacePath, m) || m)
  );
  setOutputs(result);
}

/**
 * Builds the JS client options object from the action config: backend URL plus
 * optional provider and source filters. Filters mirror remediate mode, where
 * `sources` selects vulnerability sources (not manifest paths).
 */
function buildAnalysisOptions(
  config: ActionConfig,
  backendUrl: string
): Record<string, string> {
  const opts: Record<string, string> = {
    TRUSTIFY_DA_BACKEND_URL: backendUrl,
  };
  if (config.providers?.length) {
    opts.TRUSTIFY_DA_PROVIDERS = config.providers.join(',');
  }
  if (config.sources?.length) {
    opts.TRUSTIFY_DA_SOURCES = config.sources.join(',');
  }
  return opts;
}

/** Creates a zeroed CheckResult accumulator. */
function emptyResult(): CheckResult {
  return {
    scanned: { total: 0, direct: 0, transitive: 0 },
    severity: { critical: 0, high: 0, medium: 0, low: 0 },
    vulnerabilityRows: [],
    remediations: [],
    remediationCount: 0,
    licenseCategoryCounts: new Map(),
    licenseConflicts: [],
    hasLicenseData: false,
  };
}

/**
 * Folds a single manifest's analysis report into the running aggregate: scanned
 * counts, per-source severity rows, remediations, and license data.
 */
function aggregateReport(
  result: CheckResult,
  report: AnalysisReport,
  relPath: string,
  config: ActionConfig,
  manifestPath: string
): void {
  result.scanned.total += report.scanned?.total ?? 0;
  result.scanned.direct += report.scanned?.direct ?? 0;
  result.scanned.transitive += report.scanned?.transitive ?? 0;

  for (const [providerName, provider] of Object.entries(
    report.providers ?? {}
  )) {
    for (const [sourceName, source] of Object.entries(provider.sources ?? {})) {
      const counts = countSeverities(source);
      result.severity.critical += counts.critical;
      result.severity.high += counts.high;
      result.severity.medium += counts.medium;
      result.severity.low += counts.low;
      if (counts.critical || counts.high || counts.medium || counts.low) {
        result.vulnerabilityRows.push({
          manifest: relPath,
          provider: providerName,
          source: sourceName,
          ...counts,
        });
      }
    }
  }

  // extractRemediations dedups per dependency within this report and picks the
  // best fix across providers; provider order biases that selection.
  const remediations = extractRemediations(report, {
    providerPriority: config.providers,
  });
  result.remediations.push(...remediations);
  result.remediationCount += remediations.reduce(
    (sum, r) => sum + r.vulnerabilities.length,
    0
  );

  aggregateLicenses(result, report, manifestPath);
}

/**
 * Counts vulnerabilities by severity for one source. Prefers the backend's
 * precomputed `summary`; falls back to walking each dependency's issues when the
 * summary is absent.
 */
function countSeverities(source: Source): SeverityCounts {
  if (source.summary) {
    return {
      critical: source.summary.critical ?? 0,
      high: source.summary.high ?? 0,
      medium: source.summary.medium ?? 0,
      low: source.summary.low ?? 0,
    };
  }

  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const dep of source.dependencies ?? []) {
    for (const issue of dep.issues ?? []) {
      // issue.severity is a Severity string enum; compare via String() so this
      // stays a type-only dependency (no runtime enum import into the bundle).
      switch (String(issue.severity ?? '').toUpperCase()) {
        case 'CRITICAL':
          counts.critical++;
          break;
        case 'HIGH':
          counts.high++;
          break;
        case 'MEDIUM':
          counts.medium++;
          break;
        case 'LOW':
          counts.low++;
          break;
      }
    }
  }
  return counts;
}

/**
 * Runs license analysis for one manifest and folds it into the aggregate. License
 * data is best-effort: any failure (missing licenses, unreachable backend for the
 * project category) is logged and the manifest contributes no license data rather
 * than failing the check.
 */
function aggregateLicenses(
  result: CheckResult,
  report: AnalysisReport,
  manifestPath: string
): void {
  let licenseMap: Map<string, { licenses: string[]; category?: string }>;
  try {
    licenseMap = licensesFromReport(report);
  } catch (error) {
    core.warning(
      `License analysis skipped for a manifest: ${error instanceof Error ? error.message : String(error)}`
    );
    return;
  }
  if (licenseMap.size === 0) {
    return;
  }
  result.hasLicenseData = true;

  const projectCategory = resolveProjectCategory(manifestPath);

  for (const [purl, info] of licenseMap) {
    const category = info.category || 'UNKNOWN';
    result.licenseCategoryCounts.set(
      category,
      (result.licenseCategoryCounts.get(category) ?? 0) + 1
    );

    if (getCompatibility(projectCategory, info.category) === 'incompatible') {
      result.licenseConflicts.push({
        purl,
        licenses: info.licenses,
        reason: `${category} license is incompatible with the project's ${projectCategory} license`,
      });
    }
  }
}

/**
 * Best-effort resolution of the project's own license category, used as the
 * baseline for dependency compatibility checks. Returns undefined when the
 * project license cannot be determined, in which case compatibility is treated
 * as unknown (no conflicts flagged).
 */
function resolveProjectCategory(manifestPath: string): string | undefined {
  try {
    const projectLicense = getProjectLicense(manifestPath);
    const spdx = projectLicense.fromManifest;
    if (!spdx) {
      return undefined;
    }
    // Map the manifest-declared SPDX id to a category locally, avoiding a backend
    // round-trip per manifest. Unknown ids leave the category undefined, so
    // getCompatibility reports 'unknown' and no conflict is flagged.
    return categoryFromSpdx(spdx);
  } catch {
    return undefined;
  }
}

/**
 * Maps well-known SPDX identifiers to a coarse license category without a backend
 * call, so a project license declared in the manifest can still seed
 * compatibility checks. Unknown identifiers yield undefined.
 */
function categoryFromSpdx(spdx: string): string | undefined {
  const id = spdx.toLowerCase();
  if (/(^|[^a-z])(mit|apache|bsd|isc|zlib)([^a-z]|$)/.test(id)) {
    return 'PERMISSIVE';
  }
  if (id.includes('lgpl') || id.includes('mpl') || id.includes('epl')) {
    return 'WEAK_COPYLEFT';
  }
  if (id.includes('gpl') || id.includes('agpl')) {
    return 'STRONG_COPYLEFT';
  }
  return undefined;
}

/**
 * Writes the full check report to `$GITHUB_STEP_SUMMARY` via the Actions summary
 * API. The report always renders the scanned and vulnerability sections; the
 * license section is included only when license data was available.
 */
function writeSummary(result: CheckResult, manifests: string[]): void {
  const markdown = buildSummaryMarkdown(result, manifests);
  // core.summary buffers markdown and flushes to $GITHUB_STEP_SUMMARY on write().
  void core.summary.addRaw(markdown).write();
}

/** Renders the complete check report as a markdown string. */
function buildSummaryMarkdown(
  result: CheckResult,
  manifests: string[]
): string {
  const sections: string[] = [];

  sections.push('# Trustify Dependency Analytics — Check Report');

  sections.push(
    [
      '## Dependencies Scanned',
      '',
      '| Metric | Count |',
      '| --- | --- |',
      `| Manifests | ${manifests.length} |`,
      `| Total | ${result.scanned.total} |`,
      `| Direct | ${result.scanned.direct} |`,
      `| Transitive | ${result.scanned.transitive} |`,
    ].join('\n')
  );

  sections.push(buildVulnerabilitySection(result));
  sections.push(buildRemediationSection(result));

  if (result.hasLicenseData) {
    sections.push(buildLicenseSection(result));
  }

  return sections.join('\n\n') + '\n';
}

/** Renders the vulnerabilities-by-provider/source table plus totals. */
function buildVulnerabilitySection(result: CheckResult): string {
  const lines = ['## Vulnerabilities', ''];
  if (result.vulnerabilityRows.length === 0) {
    lines.push('No vulnerabilities found.');
    return lines.join('\n');
  }

  lines.push(
    '| Manifest | Provider | Source | Critical | High | Medium | Low |'
  );
  lines.push('| --- | --- | --- | --- | --- | --- | --- |');
  for (const row of result.vulnerabilityRows) {
    lines.push(
      `| ${row.manifest} | ${row.provider} | ${row.source} | ${row.critical} | ${row.high} | ${row.medium} | ${row.low} |`
    );
  }
  lines.push(
    `| **Total** | | | ${result.severity.critical} | ${result.severity.high} | ${result.severity.medium} | ${result.severity.low} |`
  );
  return lines.join('\n');
}

/** Renders the available-remediations table. */
function buildRemediationSection(result: CheckResult): string {
  const lines = ['## Available Remediations', ''];
  if (result.remediations.length === 0) {
    lines.push('No remediations available.');
    return lines.join('\n');
  }

  lines.push('| Dependency | Current | Fixed In | Provider | Source |');
  lines.push('| --- | --- | --- | --- | --- |');
  for (const r of result.remediations) {
    const name = r.groupId ? `${r.groupId}:${r.artifactId}` : r.artifactId;
    lines.push(
      `| ${name} | ${r.currentVersion} | ${r.fixedInVersion} | ${r.provider} | ${r.source} |`
    );
  }
  return lines.join('\n');
}

/** Renders the license category breakdown and, when present, the conflicts table. */
function buildLicenseSection(result: CheckResult): string {
  const lines = ['## License Analysis', ''];

  lines.push('| Category | Dependencies |');
  lines.push('| --- | --- |');
  for (const [category, count] of result.licenseCategoryCounts) {
    lines.push(`| ${category} | ${count} |`);
  }

  if (result.licenseConflicts.length > 0) {
    lines.push('', '### License Conflicts', '');
    lines.push('| Dependency | Licenses | Reason |');
    lines.push('| --- | --- | --- |');
    for (const conflict of result.licenseConflicts) {
      lines.push(
        `| ${conflict.purl} | ${conflict.licenses.join(', ')} | ${conflict.reason} |`
      );
    }
  }

  return lines.join('\n');
}

/**
 * Publishes the structured outputs downstream steps consume for policy gates.
 * Every output is always set (0 by default) so gate expressions never see an
 * empty value.
 */
function setOutputs(result: CheckResult): void {
  core.setOutput('critical-count', result.severity.critical);
  core.setOutput('high-count', result.severity.high);
  core.setOutput('medium-count', result.severity.medium);
  core.setOutput('low-count', result.severity.low);
  core.setOutput('remediation-count', result.remediationCount);
  core.setOutput('license-conflicts', result.licenseConflicts.length);
}
