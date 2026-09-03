import * as core from '@actions/core';
import * as fs from 'fs/promises';
import * as yaml from 'yaml';

export interface ActionConfig {
  mode: string;
  backendUrl?: string;
  providers?: string[];
  sources?: string[];
  groupBy?: string;
  dryRun: boolean;
  labels?: string[];
  branchPrefix?: string;
  sbomTargets?: string[];
  configPath: string;
}

/**
 * Loads configuration from .trustify-da.yml and merges with action inputs.
 * Action inputs override config file values.
 */
export async function loadConfig(): Promise<ActionConfig> {
  const configPath = core.getInput('config-path') || '.trustify-da.yml';

  // Load config file if it exists
  let fileConfig: Record<string, unknown> = {};
  try {
    const configContent = await fs.readFile(configPath, 'utf-8');
    fileConfig = yaml.parse(configContent) as Record<string, unknown>;
  } catch (error) {
    // Config file doesn't exist or can't be read - this is okay, we'll use inputs
    core.info(`No config file found at ${configPath}, using action inputs only`);
  }

  // Read action inputs
  const mode = core.getInput('mode', { required: true });
  const backendUrl = core.getInput('backend-url');
  const providers = core.getInput('providers');
  const sources = core.getInput('sources');
  const groupBy = core.getInput('group-by');
  const dryRunInput = core.getInput('dry-run') || 'false';
  const dryRun = dryRunInput.toLowerCase() === 'true';
  const labels = core.getInput('labels');
  const branchPrefix = core.getInput('branch-prefix');
  const sbomTargets = core.getInput('sbom-targets');

  // Merge config - action inputs override file config
  const config: ActionConfig = {
    mode,
    backendUrl: backendUrl || (fileConfig.backendUrl as string),
    providers: providers
      ? providers.split(',').map((p) => p.trim())
      : (fileConfig.providers as string[]),
    sources: sources
      ? sources.split(',').map((s) => s.trim())
      : (fileConfig.sources as string[]),
    groupBy: groupBy || (fileConfig.groupBy as string),
    dryRun,
    labels: labels
      ? labels.split(',').map((l) => l.trim())
      : (fileConfig.labels as string[]) || ['trustify-da', 'security'],
    branchPrefix: branchPrefix || (fileConfig.branchPrefix as string) || 'trustify-da',
    sbomTargets: sbomTargets
      ? sbomTargets.split(',').map((t) => t.trim())
      : (fileConfig.sbomTargets as string[]),
    configPath,
  };

  return config;
}
