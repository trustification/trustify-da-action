import { mkdtemp, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, vi, beforeAll, afterEach } from 'vitest';
import * as core from '@actions/core';
import { runRemediateMode } from '../../src/modes/remediate.js';
import type { ActionConfig } from '../../src/config.js';

// Exercises remediate mode against the REAL JS client and the shared stage
// backend (no mocks). It needs a Maven toolchain and network, so it is skipped
// unless TRUSTIFY_DA_BACKEND_URL is set (see vitest.e2e.config.ts).
const here = dirname(fileURLToPath(import.meta.url));

describe.skipIf(!process.env.TRUSTIFY_DA_BACKEND_URL)('remediate mode (e2e)', () => {
  beforeAll(async () => {
    // Copy the vulnerable fixture into a throwaway workspace so remediation
    // never edits the repo's own fixture.
    const workspace = await mkdtemp(join(tmpdir(), 'trustify-da-e2e-'));
    await copyFile(join(here, '../fixtures/pom.xml'), join(workspace, 'pom.xml'));
    process.env.GITHUB_WORKSPACE = workspace;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('finds remediations for a vulnerable Maven project', async () => {
    const outputs = new Map<string, unknown>();
    vi.spyOn(core, 'setOutput').mockImplementation((name, value) => {
      outputs.set(name, value);
    });

    const config: ActionConfig = {
      mode: 'remediate',
      dryRun: true,
      groupBy: 'bundle',
      configPath: '.trustify-da.yml',
    };

    await runRemediateMode(config);

    expect(Number(outputs.get('remediation-count'))).toBeGreaterThan(0);
  });
});
