import * as core from '@actions/core';
import { loadConfig } from './config.js';
import { runRemediateMode } from './modes/remediate.js';
import { runCheckMode } from './modes/check.js';
import { runSbomMode } from './modes/sbom.js';

/**
 * Main entry point for the GitHub Action.
 * Reads inputs, loads configuration, and dispatches to the appropriate mode handler.
 */
async function run(): Promise<void> {
  try {
    // Read required mode input
    const mode = core.getInput('mode', { required: true });

    // Load and merge configuration
    const config = await loadConfig();

    // Dispatch to mode handler
    switch (mode.toLowerCase()) {
      case 'remediate':
        await runRemediateMode(config);
        break;
      case 'check':
        await runCheckMode(config);
        break;
      case 'sbom':
        await runSbomMode(config);
        break;
      default:
        throw new Error(
          `Invalid mode: ${mode}. Must be one of: remediate, check, sbom`
        );
    }
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed('An unexpected error occurred');
    }
  }
}

run();
