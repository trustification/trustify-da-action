import * as core from '@actions/core';
import type { ActionConfig } from '../config.js';

/**
 * Runs the sbom mode: generates an SBOM for the project and writes its path to
 * the sbom-path output. Upload is handled out-of-band by the caller.
 */
export async function runSbomMode(config: ActionConfig): Promise<void> {
  core.info('Running in sbom mode');
  core.info(`Configuration: ${JSON.stringify(config, null, 2)}`);

  // TODO: Implement SBOM generation
  // - Generate SBOM for the project
  // - Set output: sbom-path

  core.warning('SBOM mode is not yet implemented');
}
