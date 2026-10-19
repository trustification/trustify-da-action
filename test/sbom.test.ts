import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as core from '@actions/core';
import { runSbomMode } from '../src/modes/sbom.js';
import type { ActionConfig } from '../src/config.js';

vi.mock('@actions/core', () => {
  interface MockSummary {
    addRaw: (md: string) => MockSummary;
    write: () => Promise<MockSummary>;
  }
  const summary: MockSummary = {
    addRaw: vi.fn(() => summary),
    write: vi.fn(async () => summary),
  };
  return {
    info: vi.fn(),
    warning: vi.fn(),
    error: vi.fn(),
    setOutput: vi.fn(),
    setFailed: vi.fn(),
    getInput: vi.fn(() => ''),
    summary,
  };
});

vi.mock('@trustify-da/trustify-da-javascript-client/dist/src/index.js', () => ({
  default: { generateSbom: vi.fn() },
}));
vi.mock(
  '@trustify-da/trustify-da-javascript-client/dist/src/remediate.js',
  () => ({
    findManifests: vi.fn(),
  })
);
vi.mock('node:fs/promises', () => ({
  mkdir: vi.fn(),
  writeFile: vi.fn(),
}));

import daClient from '@trustify-da/trustify-da-javascript-client/dist/src/index.js';
import { findManifests } from '@trustify-da/trustify-da-javascript-client/dist/src/remediate.js';
import { mkdir, writeFile } from 'node:fs/promises';

const WORKSPACE = '/work';
const RUNNER_TEMP = '/tmp/runner';

function makeConfig(overrides: Partial<ActionConfig> = {}): ActionConfig {
  return {
    mode: 'sbom',
    backendUrl: null,
    providers: [],
    sources: [],
    groupBy: 'bundle',
    dryRun: false,
    labels: ['trustify-da'],
    branchPrefix: 'trustify-da',
    remediation: {},
    failOn: {},
    ...overrides,
  };
}

function makeSbom(opts: {
  name?: string;
  purl?: string;
  componentCount?: number;
}): Record<string, unknown> {
  const components = Array.from(
    { length: opts.componentCount ?? 3 },
    (_, i) => ({
      name: `dep-${i}`,
      version: '1.0.0',
      purl: `pkg:maven/com.example/dep-${i}@1.0.0`,
      type: 'library',
    })
  );
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      component: {
        name: opts.name ?? 'my-project',
        purl: opts.purl ?? 'pkg:maven/com.example/my-project@1.0.0',
        type: 'application',
      },
    },
    components,
    dependencies: [],
  };
}

function capturedSummary(): string {
  return vi
    .mocked(core.summary.addRaw)
    .mock.calls.map((call) => String(call[0]))
    .join('\n');
}

function outputValue(name: string): unknown {
  const call = vi
    .mocked(core.setOutput)
    .mock.calls.find(([outputName]) => outputName === name);
  return call?.[1];
}

describe('sbom mode', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = WORKSPACE;
    process.env.RUNNER_TEMP = RUNNER_TEMP;
  });

  it('generates an SBOM for each discovered manifest and writes files', async () => {
    vi.mocked(findManifests).mockReturnValue([`${WORKSPACE}/pom.xml`]);
    vi.mocked(daClient.generateSbom).mockResolvedValue(
      makeSbom({ name: 'my-app', componentCount: 5 })
    );

    await runSbomMode(makeConfig());

    expect(daClient.generateSbom).toHaveBeenCalledWith(
      `${WORKSPACE}/pom.xml`,
      {}
    );
    expect(mkdir).toHaveBeenCalledWith(
      `${RUNNER_TEMP}/trustify-da-sboms`,
      { recursive: true }
    );
    expect(writeFile).toHaveBeenCalledWith(
      `${RUNNER_TEMP}/trustify-da-sboms/pom.xml.cdx.json`,
      expect.stringContaining('"bomFormat"')
    );
  });

  it('sets sbom-path output to the output directory', async () => {
    vi.mocked(findManifests).mockReturnValue([`${WORKSPACE}/pom.xml`]);
    vi.mocked(daClient.generateSbom).mockResolvedValue(makeSbom({}));

    await runSbomMode(makeConfig());

    expect(outputValue('sbom-path')).toBe(`${RUNNER_TEMP}/trustify-da-sboms`);
  });

  it('writes a markdown summary with manifest and component info', async () => {
    vi.mocked(findManifests).mockReturnValue([
      `${WORKSPACE}/pom.xml`,
      `${WORKSPACE}/sub/pom.xml`,
    ]);
    vi.mocked(daClient.generateSbom)
      .mockResolvedValueOnce(makeSbom({ name: 'root', componentCount: 10 }))
      .mockResolvedValueOnce(makeSbom({ name: 'sub-mod', componentCount: 4 }));

    await runSbomMode(makeConfig());

    const md = capturedSummary();
    expect(md).toContain('# Trustify Dependency Analytics — SBOM Report');
    expect(md).toContain('## Generated SBOMs');
    expect(md).toContain('| pom.xml | root | 10 | pom.xml.cdx.json |');
    expect(md).toContain(
      '| sub/pom.xml | sub-mod | 4 | sub-pom.xml.cdx.json |'
    );
    expect(core.summary.write).toHaveBeenCalledOnce();
  });

  it('flattens nested manifest paths into safe filenames', async () => {
    vi.mocked(findManifests).mockReturnValue([
      `${WORKSPACE}/deeply/nested/pom.xml`,
    ]);
    vi.mocked(daClient.generateSbom).mockResolvedValue(makeSbom({}));

    await runSbomMode(makeConfig());

    expect(writeFile).toHaveBeenCalledWith(
      `${RUNNER_TEMP}/trustify-da-sboms/deeply-nested-pom.xml.cdx.json`,
      expect.any(String)
    );
  });

  it('handles zero manifests gracefully', async () => {
    vi.mocked(findManifests).mockReturnValue([]);

    await runSbomMode(makeConfig());

    expect(daClient.generateSbom).not.toHaveBeenCalled();
    expect(outputValue('sbom-path')).toBe('');
    const md = capturedSummary();
    expect(md).toContain('No SBOMs generated.');
  });

  it('throws when generateSbom fails', async () => {
    vi.mocked(findManifests).mockReturnValue([`${WORKSPACE}/pom.xml`]);
    vi.mocked(daClient.generateSbom).mockRejectedValue(
      new Error('unsupported ecosystem')
    );

    await expect(runSbomMode(makeConfig())).rejects.toThrow(
      /SBOM generation failed for pom\.xml: unsupported ecosystem/
    );
  });

  it('falls back to workspace path when RUNNER_TEMP is unset', async () => {
    delete process.env.RUNNER_TEMP;
    vi.mocked(findManifests).mockReturnValue([`${WORKSPACE}/pom.xml`]);
    vi.mocked(daClient.generateSbom).mockResolvedValue(makeSbom({}));

    await runSbomMode(makeConfig());

    expect(mkdir).toHaveBeenCalledWith(
      `${WORKSPACE}/trustify-da-sboms`,
      { recursive: true }
    );
    expect(outputValue('sbom-path')).toBe(`${WORKSPACE}/trustify-da-sboms`);
  });

  it('deduplicates filenames when flattened paths collide', async () => {
    vi.mocked(findManifests).mockReturnValue([
      `${WORKSPACE}/a/pom.xml`,
      `${WORKSPACE}/a-pom.xml`,
    ]);
    vi.mocked(daClient.generateSbom).mockResolvedValue(makeSbom({}));

    await runSbomMode(makeConfig());

    const writeCalls = vi.mocked(writeFile).mock.calls.map((c) => c[0]);
    expect(writeCalls[0]).toBe(`${RUNNER_TEMP}/trustify-da-sboms/a-pom.xml.cdx.json`);
    expect(writeCalls[1]).toBe(`${RUNNER_TEMP}/trustify-da-sboms/a-pom.xml.2.cdx.json`);
  });

  it('handles an SBOM with missing metadata gracefully', async () => {
    vi.mocked(findManifests).mockReturnValue([`${WORKSPACE}/pom.xml`]);
    vi.mocked(daClient.generateSbom).mockResolvedValue({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      components: [],
    });

    await runSbomMode(makeConfig());

    const md = capturedSummary();
    expect(md).toContain('| pom.xml | unknown | 0 |');
    expect(outputValue('sbom-path')).toBe(`${RUNNER_TEMP}/trustify-da-sboms`);
  });
});
