import * as core from '@actions/core';
import type { ActionConfig } from '../config.js';

/**
 * Runs the check mode: analyzes dependencies and reports findings without creating PRs.
 */
export async function runCheckMode(config: ActionConfig): Promise<void> {
  core.info('Running in check mode');
  core.info(`Configuration: ${JSON.stringify(config, null, 2)}`);

  // TODO: Implement check mode logic
  // - Analyze dependencies for vulnerabilities
  // - Generate workflow summary with findings
  // - Set structured outputs for CI integration
  // - Set outputs: critical-count, high-count, medium-count, low-count, license-conflicts

  core.warning('Check mode is not yet implemented');
}
