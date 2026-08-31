import * as core from '@actions/core';
import type { ActionConfig } from '../config.js';

/**
 * Runs the sbom mode: generates SBOM and uploads to configured targets.
 */
export async function runSbomMode(config: ActionConfig): Promise<void> {
  core.info('Running in sbom mode');
  core.info(`Configuration: ${JSON.stringify(config, null, 2)}`);

  // TODO: Implement sbom mode logic
  // - Generate SBOM for the project
  // - Upload to configured targets (artifact, OCI registry)
  // - Set outputs: sbom-path

  core.warning('SBOM mode is not yet implemented');
}
