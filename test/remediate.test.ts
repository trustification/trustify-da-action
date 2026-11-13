import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { runRemediateMode } from '../src/modes/remediate.js';
import type { ActionConfig } from '../src/config.js';

// Mock dependencies
vi.mock('@actions/core');
vi.mock('@actions/exec');

vi.mock('@trustify-da/trustify-da-javascript-client/dist/src/remediate.js', () => {
  const rem = {
    purl: 'pkg:maven/com.example/vulnerable@1.0.0',
    groupId: 'com.example',
    artifactId: 'vulnerable',
    currentVersion: '1.0.0',
    fixedInVersion: '1.1.0',
    fixedInPurl: 'pkg:maven/com.example/vulnerable@1.1.0',
    provider: 'osv',
    source: 'osv',
    vulnerabilities: [
      { id: 'CVE-2024-1234', severity: 'HIGH', advisories: [{ id: 'GHSA-1234', url: 'https://github.com/advisories/GHSA-1234' }] },
      { id: 'CVE-2024-5678', severity: 'HIGH', advisories: [] },
    ],
    files: ['pom.xml'],
  };
  return {
    runRemediation: vi.fn().mockResolvedValue({
      exitCode: 0,
      manifests: [],
      appliedFiles: [],
      skipped: [],
      groups: [
        {
          changeKey: 'mvn:direct:pom.xml:com.example:vulnerable',
          appliedVersion: '1.1.0',
          remediations: [rem],
          edit: { path: 'pom.xml', after: '<pom><vulnerable>1.1.0</vulnerable></pom>' },
          divergent: false,
        },
      ],
      remediations: [rem],
    }),
  };
});
vi.mock('@trustify-da/trustify-da-javascript-client/dist/src/remediation_report.js', () => ({
  generateReport: vi.fn().mockReturnValue('# Remediation Report\n\nFixed 2 vulnerabilities'),
}));
vi.mock('../src/github.js', () => ({
  createOrUpdatePR: vi.fn().mockResolvedValue('https://github.com/test/repo/pull/1'),
}));
vi.mock('node:fs/promises', () => ({
  writeFile: vi.fn().mockResolvedValue(undefined),
}));

function makeRemediation(overrides: Record<string, unknown> = {}) {
  return {
    purl: 'pkg:maven/com.example/vulnerable@1.0.0',
    groupId: 'com.example',
    artifactId: 'vulnerable',
    currentVersion: '1.0.0',
    fixedInVersion: '1.1.0',
    fixedInPurl: 'pkg:maven/com.example/vulnerable@1.1.0',
    provider: 'osv',
    source: 'osv',
    vulnerabilities: [{ id: 'CVE-0000-0000', severity: 'HIGH', advisories: [] }],
    files: ['pom.xml'],
    ...overrides,
  };
}

function makeGroup(overrides: Record<string, unknown> = {}) {
  const remediations = (overrides.remediations as ReturnType<typeof makeRemediation>[]) ?? [makeRemediation()];
  return {
    changeKey: 'mvn:direct:pom.xml:com.example:vulnerable',
    appliedVersion: '1.1.0',
    remediations,
    edit: { path: 'pom.xml', after: '<pom><vulnerable>1.1.0</vulnerable></pom>' },
    divergent: false,
    ...overrides,
  };
}

describe('remediate mode', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = '/tmp/test-workspace';
    process.env.GITHUB_TOKEN = 'test-token';
    process.env.TRUSTIFY_DA_BACKEND_URL = 'https://trustify.test';

    vi.mocked(exec.getExecOutput).mockImplementation(async (cmd, args) => {
      if (cmd === 'git' && args?.[0] === 'rev-parse') {
        return { stdout: 'basesha0000000000000000000000000000000000\n', stderr: '', exitCode: 0 };
      }
      if (cmd === 'git' && args?.[0] === 'diff') {
        return { stdout: 'pom.xml\n', stderr: '', exitCode: 0 };
      }
      return { stdout: '', stderr: '', exitCode: 0 };
    });
  });

  it('should run remediation and create PR when files are modified', async () => {
    vi.mocked(exec.exec).mockImplementation(async (cmd, args, options) => {
      if (cmd === 'git' && args?.[0] === 'diff') {
        options?.listeners?.stdout?.(Buffer.from('pom.xml\n'));
      }
      if (cmd === 'git' && args?.[0] === 'branch') {
        options?.listeners?.stdout?.(Buffer.from('main'));
      }
      return 0;
    });

    const config: ActionConfig = {
      mode: 'remediate',
      backendUrl: null,
      providers: [],
      sources: [],
      groupBy: 'bundle',
      dryRun: false,
      labels: ['trustify-da', 'security'],
      branchPrefix: 'trustify-da',
      remediation: {},
      failOn: {},
    };

    await runRemediateMode(config);

    expect(core.setOutput).toHaveBeenCalledWith('changed-files', 'pom.xml');
    expect(core.setOutput).toHaveBeenCalledWith('remediation-count', 2);
    expect(core.setOutput).toHaveBeenCalledWith('pr-url', 'https://github.com/test/repo/pull/1');
  });

  it('should skip PR creation in dry-run mode', async () => {
    const { runRemediation } = await import(
      '@trustify-da/trustify-da-javascript-client/dist/src/remediate.js'
    );

    const config: ActionConfig = {
      mode: 'remediate',
      backendUrl: null,
      providers: [],
      sources: [],
      groupBy: 'bundle',
      dryRun: true,
      labels: ['trustify-da'],
      branchPrefix: 'trustify-da',
      remediation: {},
      failOn: {},
    };

    await runRemediateMode(config);

    expect(runRemediation).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ dryRun: true })
    );

    const gitCalls = vi.mocked(exec.exec).mock.calls.filter((call) => call[0] === 'git');
    expect(gitCalls.length).toBe(0);
  });

  it('passes remediation.exclude from config to runRemediation', async () => {
    const { runRemediation } = await import(
      '@trustify-da/trustify-da-javascript-client/dist/src/remediate.js'
    );

    const config: ActionConfig = {
      mode: 'remediate',
      backendUrl: null,
      providers: [],
      sources: [],
      groupBy: 'bundle',
      dryRun: true,
      labels: ['trustify-da'],
      branchPrefix: 'trustify-da',
      remediation: { exclude: ['pkg:maven/com.example/*', 'pkg:npm/@scope/*'] },
      failOn: {},
    };

    await runRemediateMode(config);

    expect(runRemediation).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        exclude: ['pkg:maven/com.example/*', 'pkg:npm/@scope/*'],
      })
    );
  });

  it('should exit early when no remediations are found', async () => {
    const { runRemediation } = await import(
      '@trustify-da/trustify-da-javascript-client/dist/src/remediate.js'
    );
    vi.mocked(runRemediation).mockResolvedValueOnce({
      exitCode: 0, groups: [], remediations: [], manifests: [], appliedFiles: [], skipped: [],
    });

    const config: ActionConfig = {
      mode: 'remediate',
      backendUrl: null,
      providers: [],
      sources: [],
      groupBy: 'bundle',
      dryRun: false,
      labels: ['trustify-da'],
      branchPrefix: 'trustify-da',
      remediation: {},
      failOn: {},
    };

    await runRemediateMode(config);

    expect(core.setOutput).toHaveBeenCalledWith('remediation-count', 0);

    const gitCalls = vi.mocked(exec.exec).mock.calls.filter((call) => call[0] === 'git');
    expect(gitCalls.length).toBe(0);
  });

  it('should use custom labels and branch prefix from config', async () => {
    const { createOrUpdatePR } = await import('../src/github.js');

    vi.mocked(exec.exec).mockImplementation(async (cmd, args, options) => {
      if (cmd === 'git' && args?.[0] === 'diff') {
        options?.listeners?.stdout?.(Buffer.from('pom.xml\n'));
      }
      if (cmd === 'git' && args?.[0] === 'branch') {
        options?.listeners?.stdout?.(Buffer.from('main'));
      }
      return 0;
    });

    const config: ActionConfig = {
      mode: 'remediate',
      backendUrl: null,
      providers: [],
      sources: [],
      groupBy: 'bundle',
      dryRun: false,
      labels: ['custom-label', 'vulnerability'],
      branchPrefix: 'custom-prefix',
      remediation: {},
      failOn: {},
    };

    await runRemediateMode(config);

    expect(createOrUpdatePR).toHaveBeenCalledWith(
      expect.objectContaining({
        head: 'custom-prefix/remediate-vulnerabilities',
        labels: ['custom-label', 'vulnerability'],
      }),
      expect.any(Object)
    );
  });

  it('passes groups and skipped to generateReport for the PR body', async () => {
    const { runRemediation } = await import(
      '@trustify-da/trustify-da-javascript-client/dist/src/remediate.js'
    );
    const { generateReport } = await import(
      '@trustify-da/trustify-da-javascript-client/dist/src/remediation_report.js'
    );

    const rem1 = makeRemediation({ fixedInVersion: '1.10.0' });
    const rem2 = makeRemediation({
      artifactId: 'commons-lang3',
      fixedInVersion: '1.9.0',
    });
    const group = makeGroup({
      changeKey: 'mvn:prop:pom.xml:commons.version',
      appliedVersion: '1.10.0',
      remediations: [rem1, rem2],
      divergent: true,
    });
    const skipped = [
      { groupId: 'com.example', artifactId: 'legacy', newVersion: '2.0.0', reason: 'Shares a Maven property with excluded dependency' },
    ];

    vi.mocked(runRemediation).mockResolvedValueOnce({
      exitCode: 0,
      manifests: [],
      appliedFiles: [],
      skipped,
      groups: [group],
      remediations: [rem1, rem2],
    });

    vi.mocked(exec.exec).mockResolvedValue(0);

    const config: ActionConfig = {
      mode: 'remediate',
      backendUrl: null,
      providers: [],
      sources: [],
      groupBy: 'bundle',
      dryRun: false,
      labels: ['trustify-da'],
      branchPrefix: 'trustify-da',
      remediation: {},
      failOn: {},
    };

    await runRemediateMode(config);

    // generateReport is called twice: once for the info-log, once for the PR body.
    // Both should receive groups and skipped.
    for (const call of vi.mocked(generateReport).mock.calls) {
      expect(call[1]).toEqual(
        expect.objectContaining({
          groups: [group],
          skipped,
        })
      );
    }
  });

  describe('per-dependency mode (groupBy: dependency)', () => {
    beforeEach(() => {
      vi.mocked(exec.exec).mockImplementation(async (cmd, args, options) => {
        if (cmd === 'git' && args?.[0] === 'branch') {
          options?.listeners?.stdout?.(Buffer.from('main'));
        }
        return 0;
      });
    });

    it('creates one PR per group (two separate deps in one pom)', async () => {
      const { runRemediation } = await import(
        '@trustify-da/trustify-da-javascript-client/dist/src/remediate.js'
      );
      const { writeFile } = await import('node:fs/promises');
      const { createOrUpdatePR } = await import('../src/github.js');

      const rem1 = makeRemediation({
        purl: 'pkg:maven/org.apache.commons/commons-text@1.9',
        groupId: 'org.apache.commons',
        artifactId: 'commons-text',
        currentVersion: '1.9',
        fixedInVersion: '1.10.0',
        fixedInPurl: 'pkg:maven/org.apache.commons/commons-text@1.10.0',
        vulnerabilities: [{ id: 'CVE-2022-42889', severity: 'HIGH', advisories: [] }],
      });
      const rem2 = makeRemediation({
        purl: 'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.0',
        groupId: 'com.fasterxml.jackson.core',
        artifactId: 'jackson-databind',
        currentVersion: '2.14.0',
        fixedInVersion: '2.15.0',
        fixedInPurl: 'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.0',
        vulnerabilities: [{ id: 'CVE-2023-0001', severity: 'HIGH', advisories: [] }],
      });

      vi.mocked(runRemediation).mockResolvedValueOnce({
        exitCode: 0,
        manifests: [],
        appliedFiles: [],
        skipped: [],
        groups: [
          makeGroup({
            changeKey: 'mvn:direct:pom.xml:org.apache.commons:commons-text',
            appliedVersion: '1.10.0',
            remediations: [rem1],
            edit: { path: 'pom.xml', after: '<pom><commons-text>1.10.0</commons-text><jackson>2.14.0</jackson></pom>' },
          }),
          makeGroup({
            changeKey: 'mvn:direct:pom.xml:com.fasterxml.jackson.core:jackson-databind',
            appliedVersion: '2.15.0',
            remediations: [rem2],
            edit: { path: 'pom.xml', after: '<pom><commons-text>1.9</commons-text><jackson>2.15.0</jackson></pom>' },
          }),
        ],
        remediations: [rem1, rem2],
      });

      const config: ActionConfig = {
        mode: 'remediate',
        backendUrl: null,
        providers: [],
        sources: [],
        groupBy: 'dependency',
        dryRun: false,
        labels: ['trustify-da'],
        branchPrefix: 'trustify-da',
        remediation: {},
        failOn: {},
      };

      await runRemediateMode(config);

      expect(createOrUpdatePR).toHaveBeenCalledTimes(2);
      expect(writeFile).toHaveBeenCalledTimes(2);
      expect(core.setOutput).toHaveBeenCalledWith(
        'pr-url',
        'https://github.com/test/repo/pull/1,https://github.com/test/repo/pull/1'
      );

      // Each group must checkout its branch BEFORE materializing the edit.
      const checkoutOrders = vi
        .mocked(exec.exec)
        .mock.calls.map((call, i) => ({ call, order: vi.mocked(exec.exec).mock.invocationCallOrder[i] }))
        .filter(({ call }) => call[0] === 'git' && call[1]?.[0] === 'checkout' && call[1]?.[1] === '-B')
        .map(({ order }) => order);
      const writeOrders = vi.mocked(writeFile).mock.invocationCallOrder;
      expect(checkoutOrders).toHaveLength(2);
      expect(writeOrders).toHaveLength(2);
      expect(checkoutOrders[0]).toBeLessThan(writeOrders[0]);
      expect(writeOrders[0]).toBeLessThan(checkoutOrders[1]);
      expect(checkoutOrders[1]).toBeLessThan(writeOrders[1]);
    });

    it('collapses deps sharing a changeKey into one PR (shared maven property)', async () => {
      const { runRemediation } = await import(
        '@trustify-da/trustify-da-javascript-client/dist/src/remediate.js'
      );
      const { writeFile } = await import('node:fs/promises');
      const { createOrUpdatePR } = await import('../src/github.js');
      const { generateReport } = await import(
        '@trustify-da/trustify-da-javascript-client/dist/src/remediation_report.js'
      );

      const rem1 = makeRemediation({
        purl: 'pkg:maven/org.apache.commons/commons-text@1.9',
        groupId: 'org.apache.commons',
        artifactId: 'commons-text',
        currentVersion: '1.9',
        fixedInVersion: '1.10.0',
        fixedInPurl: 'pkg:maven/org.apache.commons/commons-text@1.10.0',
        vulnerabilities: [{ id: 'CVE-2022-42889', severity: 'HIGH', advisories: [] }],
      });
      const rem2 = makeRemediation({
        purl: 'pkg:maven/org.apache.commons/commons-lang3@3.11',
        groupId: 'org.apache.commons',
        artifactId: 'commons-lang3',
        currentVersion: '3.11',
        fixedInVersion: '1.9.0',
        fixedInPurl: 'pkg:maven/org.apache.commons/commons-lang3@1.9.0',
        vulnerabilities: [{ id: 'CVE-2023-0002', severity: 'MEDIUM', advisories: [] }],
      });

      const sharedAfter = '<pom><commons.version>1.10.0</commons.version></pom>';
      vi.mocked(runRemediation).mockResolvedValueOnce({
        exitCode: 0,
        manifests: [],
        appliedFiles: [],
        skipped: [],
        groups: [
          makeGroup({
            changeKey: 'mvn:prop:pom.xml:commons.version',
            appliedVersion: '1.10.0',
            remediations: [rem1, rem2],
            edit: { path: 'pom.xml', after: sharedAfter },
            divergent: true,
          }),
        ],
        remediations: [rem1, rem2],
      });

      const config: ActionConfig = {
        mode: 'remediate',
        backendUrl: null,
        providers: [],
        sources: [],
        groupBy: 'dependency',
        dryRun: false,
        labels: ['trustify-da'],
        branchPrefix: 'trustify-da',
        remediation: {},
        failOn: {},
      };

      await runRemediateMode(config);

      // One group => one PR, one write
      expect(createOrUpdatePR).toHaveBeenCalledTimes(1);
      expect(writeFile).toHaveBeenCalledTimes(1);
      expect(core.setOutput).toHaveBeenCalledWith('remediation-count', 2);

      // The PR body call to generateReport should receive the groups (with
      // divergent: true) — divergence rendering is now delegated to the report
      // generator, not the action.
      const bodyCall = vi.mocked(generateReport).mock.calls.at(-1);
      expect(bodyCall?.[1]).toEqual(
        expect.objectContaining({
          groups: expect.arrayContaining([
            expect.objectContaining({ divergent: true, appliedVersion: '1.10.0' }),
          ]),
        })
      );

      // fixedInVersion should NOT be overridden — each dep keeps its original
      // recommendation; the divergence table in the report handles the explanation.
      expect(bodyCall?.[0]).toHaveLength(2);
      const versions = bodyCall?.[0].map((r) => r.fixedInVersion);
      expect(versions).toContain('1.10.0');
      expect(versions).toContain('1.9.0');
    });

    it('pins --force-with-lease to the branch remote SHA when it already exists', async () => {
      const { runRemediation } = await import(
        '@trustify-da/trustify-da-javascript-client/dist/src/remediate.js'
      );

      const existingSha = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
      vi.mocked(exec.getExecOutput).mockImplementation(async (cmd, args) => {
        if (cmd === 'git' && args?.[0] === 'rev-parse') {
          return { stdout: 'basesha\n', stderr: '', exitCode: 0 };
        }
        if (cmd === 'git' && args?.[0] === 'ls-remote') {
          return { stdout: `${existingSha}\trefs/heads/some-branch\n`, stderr: '', exitCode: 0 };
        }
        return { stdout: '', stderr: '', exitCode: 0 };
      });

      const rem = makeRemediation({
        groupId: 'org.apache.commons',
        artifactId: 'commons-text',
        fixedInVersion: '1.10.0',
        vulnerabilities: [{ id: 'CVE-2022-42889', severity: 'HIGH', advisories: [] }],
      });

      vi.mocked(runRemediation).mockResolvedValueOnce({
        exitCode: 0,
        manifests: [],
        appliedFiles: [],
        skipped: [],
        groups: [
          makeGroup({
            changeKey: 'mvn:direct:pom.xml:org.apache.commons:commons-text',
            appliedVersion: '1.10.0',
            remediations: [rem],
            edit: { path: 'pom.xml', after: '<pom/>' },
          }),
        ],
        remediations: [rem],
      });

      const config: ActionConfig = {
        mode: 'remediate',
        backendUrl: null,
        providers: [],
        sources: [],
        groupBy: 'dependency',
        dryRun: false,
        labels: ['trustify-da'],
        branchPrefix: 'trustify-da',
        remediation: {},
        failOn: {},
      };

      await runRemediateMode(config);

      const pushCall = vi
        .mocked(exec.exec)
        .mock.calls.find((call) => call[0] === 'git' && call[1]?.[0] === 'push');
      expect(pushCall).toBeDefined();
      expect(
        pushCall?.[1]?.some((a) => a.startsWith('--force-with-lease=') && a.endsWith(`:${existingSha}`))
      ).toBe(true);
      expect(pushCall?.[1]).not.toContain('-u');
    });
  });
});
