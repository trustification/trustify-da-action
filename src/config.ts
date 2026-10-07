import * as core from '@actions/core';
import {
  resolveConfig,
  type RemediationConfig,
  type CheckConfig,
} from '@trustify-da/trustify-da-javascript-client/dist/src/config.js';

/** Resolved fail-on thresholds for check mode policy gates. */
export interface FailOnThresholds {
  critical?: number;
  high?: number;
  licenseConflicts?: number;
}

export interface ActionConfig {
  mode: string;
  backendUrl: string | null;
  providers: string[];
  sources: string[];
  groupBy: string;
  dryRun: boolean;
  labels: string[];
  branchPrefix: string;
  sbomTargets?: string[];
  remediation: RemediationConfig;
  failOn: FailOnThresholds;
}

/**
 * Loads `.trustify-da.yml` (via the JS client's directory-walking discovery) and
 * merges it with action inputs and environment variables. Precedence for
 * top-level fields (backend-url, providers, sources, group-by): action input >
 * env var > config file > hardcoded default.
 *
 * Remediation-specific fields (labels, branch-prefix) follow a similar chain:
 * action input > config file > default.
 */
export async function loadConfig(workspacePath?: string): Promise<ActionConfig> {
  const workspace = workspacePath || process.env.GITHUB_WORKSPACE || process.cwd();

  const mode = core.getInput('mode', { required: true });
  const backendUrlInput = core.getInput('backend-url') || undefined;
  const providersInput = core.getInput('providers') || undefined;
  const sourcesInput = core.getInput('sources') || undefined;
  const groupByInput = core.getInput('group-by') || undefined;
  const dryRun = (core.getInput('dry-run') || 'false').toLowerCase() === 'true';
  const labelsInput = core.getInput('labels');
  const branchPrefixInput = core.getInput('branch-prefix');
  const sbomTargetsInput = core.getInput('sbom-targets');

  const resolved = resolveConfig(
    workspace,
    {
      backendUrl: backendUrlInput,
      providers: providersInput,
      sources: sourcesInput,
      groupBy: groupByInput,
    },
    process.env as Record<string, string | undefined>,
  );

  const remediation = (resolved.remediation ?? {}) as RemediationConfig;
  const check = (resolved.check ?? {}) as CheckConfig;

  if (!['bundle', 'dependency'].includes(resolved.groupBy)) {
    core.warning(
      `Unexpected value '${resolved.groupBy}' found for 'groupBy', expected one of 'bundle'/'dependency'. Falling back to 'dependency'.`,
    );
  }

  // Labels: action input ∪ remediation.labels from config, deduplicated.
  // Default to ['trustify-da'] when neither source provides any.
  const inputLabels = labelsInput
    ? labelsInput.split(',').map((l) => l.trim()).filter(Boolean)
    : [];
  const configLabels = remediation.labels ?? [];
  const mergedLabels = [...new Set([...inputLabels, ...configLabels])];
  const labels = mergedLabels.length > 0 ? mergedLabels : ['trustify-da'];

  // Branch prefix: action input > remediation.branch-prefix > default.
  // Strip trailing '/' — the branch-name template adds a separator.
  const rawPrefix = branchPrefixInput || remediation['branch-prefix'] || 'trustify-da';
  const branchPrefix = rawPrefix.replace(/\/+$/, '') || 'trustify-da';

  const failOn: FailOnThresholds = {
    critical: resolveThreshold(core.getInput('fail-on-critical'), check['fail-on']?.critical),
    high: resolveThreshold(core.getInput('fail-on-high'), check['fail-on']?.high),
    licenseConflicts: resolveThreshold(core.getInput('fail-on-license-conflicts'), check['fail-on']?.['license-conflicts']),
  };

  return {
    mode,
    backendUrl: resolved.backendUrl,
    providers: resolved.providers,
    sources: resolved.sources,
    groupBy: ['bundle', 'dependency'].includes(resolved.groupBy) ? resolved.groupBy : 'dependency',
    dryRun,
    labels,
    branchPrefix,
    sbomTargets: sbomTargetsInput
      ? sbomTargetsInput.split(',').map((t) => t.trim())
      : undefined,
    remediation,
    failOn,
  };
}

/**
 * Merges an action input threshold with a config file threshold. Returns the
 * action input when explicitly set (including `false` to disable a config-level
 * gate), otherwise falls back to the config file value.
 */
function resolveThreshold(input: string, configValue: number | undefined): number | undefined {
  const parsed = parseThreshold(input);
  if (parsed === undefined) return configValue;
  return parsed ?? undefined;
}

/**
 * Parses a threshold value from an action input string. Returns:
 * - `number` for a valid integer or `true` (mapped to 0)
 * - `null` for an explicit `false` (disables the gate, overriding config)
 * - `undefined` for empty/absent input (falls through to config file)
 */
function parseThreshold(value: string): number | null | undefined {
  const trimmed = value.trim();
  if (trimmed === '') return undefined;
  if (trimmed.toLowerCase() === 'true') return 0;
  if (trimmed.toLowerCase() === 'false') return null;
  const parsed = Number.parseInt(trimmed, 10);
  if (Number.isNaN(parsed) || parsed < 0) {
    core.warning(`Invalid threshold value '${trimmed}' — expected a non-negative integer or true/false. Ignoring.`);
    return undefined;
  }
  return parsed;
}
