import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { runRemediateMode } from '../src/modes/remediate.js';
import type { ActionConfig } from '../src/config.js';

// Mock dependencies
vi.mock('@actions/core');
vi.mock('@actions/exec');
vi.mock('@trustify-da/trustify-da-javascript-client/dist/src/remediate.js', () => ({
  runRemediation: vi.fn().mockResolvedValue({
    exitCode: 0,
    remediations: [
      {
        purl: 'pkg:maven/com.example/vulnerable@1.0.0',
        groupId: 'com.example',
        artifactId: 'vulnerable',
        currentVersion: '1.0.0',
        fixedInVersion: '1.1.0',
        fixedInPurl: 'pkg:maven/com.example/vulnerable@1.1.0',
        provider: 'osv',
        source: 'osv',
        severity: 'HIGH',
        cves: ['CVE-2024-1234', 'CVE-2024-5678'],
        advisories: [{ id: 'GHSA-1234', url: 'https://github.com/advisories/GHSA-1234' }],
        files: ['pom.xml'],
      },
    ],
  }),
}));
vi.mock('@trustify-da/trustify-da-javascript-client/dist/src/remediation_report.js', () => ({
  generateReport: vi.fn().mockReturnValue('# Remediation Report\n\nFixed 2 vulnerabilities'),
}));
vi.mock('../src/github.js', () => ({
  createOrUpdatePR: vi.fn().mockResolvedValue('https://github.com/test/repo/pull/1'),
}));
vi.mock('node:fs/promises', () => ({
  writeFile: vi.fn().mockResolvedValue(undefined),
}));

describe('remediate mode', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = '/tmp/test-workspace';
    process.env.GITHUB_TOKEN = 'test-token';
    process.env.TRUSTIFY_DA_BACKEND_URL = 'https://trustify.test';
  });

  it('should run remediation and create PR when files are modified', async () => {
    // Mock git operations
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
      dryRun: false,
      labels: ['trustify-da', 'security'],
      branchPrefix: 'trustify-da',
      configPath: '.trustify-da.yml',
    };

    await runRemediateMode(config);

    // Verify outputs were set - 2 CVEs total
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
      dryRun: true,
      configPath: '.trustify-da.yml',
    };

    await runRemediateMode(config);

    // Verify runRemediation was called with dryRun: true
    expect(runRemediation).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ dryRun: true })
    );

    // Verify no git operations were performed
    const gitCalls = vi.mocked(exec.exec).mock.calls.filter((call) => call[0] === 'git');
    expect(gitCalls.length).toBe(0);
  });

  it('should exit early when no remediations are found', async () => {
    const { runRemediation } = await import(
      '@trustify-da/trustify-da-javascript-client/dist/src/remediate.js'
    );
    vi.mocked(runRemediation).mockResolvedValueOnce({ exitCode: 0, remediations: [] });

    const config: ActionConfig = {
      mode: 'remediate',
      dryRun: false,
      configPath: '.trustify-da.yml',
    };

    await runRemediateMode(config);

    // Verify remediation-count is 0
    expect(core.setOutput).toHaveBeenCalledWith('remediation-count', 0);

    // Verify no git operations
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
      dryRun: false,
      labels: ['custom-label', 'vulnerability'],
      branchPrefix: 'custom-prefix',
      configPath: '.trustify-da.yml',
    };

    await runRemediateMode(config);

    // Verify createOrUpdatePR was called with custom labels and branch
    expect(createOrUpdatePR).toHaveBeenCalledWith(
      expect.objectContaining({
        head: 'custom-prefix/remediate-vulnerabilities',
        labels: ['custom-label', 'vulnerability'],
      }),
      expect.any(Object)
    );
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

    it('creates one PR per distinct changeKey (two separate deps in one pom)', async () => {
      const { runRemediation } = await import(
        '@trustify-da/trustify-da-javascript-client/dist/src/remediate.js'
      );
      const { writeFile } = await import('node:fs/promises');
      const { createOrUpdatePR } = await import('../src/github.js');

      vi.mocked(runRemediation).mockResolvedValueOnce({
        exitCode: 0,
        remediations: [
          {
            purl: 'pkg:maven/org.apache.commons/commons-text@1.9',
            groupId: 'org.apache.commons',
            artifactId: 'commons-text',
            currentVersion: '1.9',
            fixedInVersion: '1.10.0',
            fixedInPurl: 'pkg:maven/org.apache.commons/commons-text@1.10.0',
            provider: 'osv',
            source: 'osv',
            severity: 'HIGH',
            cves: ['CVE-2022-42889'],
            advisories: [],
            files: ['pom.xml'],
            changes: [
              {
                path: 'pom.xml',
                after: '<pom><commons-text>1.10.0</commons-text><jackson>2.14.0</jackson></pom>',
                changeKey: 'mvn:direct:pom.xml:org.apache.commons:commons-text',
              },
            ],
          },
          {
            purl: 'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.0',
            groupId: 'com.fasterxml.jackson.core',
            artifactId: 'jackson-databind',
            currentVersion: '2.14.0',
            fixedInVersion: '2.15.0',
            fixedInPurl: 'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.0',
            provider: 'osv',
            source: 'osv',
            severity: 'HIGH',
            cves: ['CVE-2023-0001'],
            advisories: [],
            files: ['pom.xml'],
            changes: [
              {
                path: 'pom.xml',
                after: '<pom><commons-text>1.9</commons-text><jackson>2.15.0</jackson></pom>',
                changeKey: 'mvn:direct:pom.xml:com.fasterxml.jackson.core:jackson-databind',
              },
            ],
          },
        ],
      });

      const config: ActionConfig = {
        mode: 'remediate',
        dryRun: false,
        groupBy: 'dependency',
        branchPrefix: 'trustify-da',
        configPath: '.trustify-da.yml',
      };

      await runRemediateMode(config);

      // Two distinct changeKeys => two PRs
      expect(createOrUpdatePR).toHaveBeenCalledTimes(2);
      // Two isolated writes of `after` content
      expect(writeFile).toHaveBeenCalledTimes(2);
      // pr-url output is comma-joined for multiple PRs
      expect(core.setOutput).toHaveBeenCalledWith(
        'pr-url',
        'https://github.com/test/repo/pull/1,https://github.com/test/repo/pull/1'
      );
    });

    it('collapses deps sharing a changeKey into one PR (shared maven property)', async () => {
      const { runRemediation } = await import(
        '@trustify-da/trustify-da-javascript-client/dist/src/remediate.js'
      );
      const { writeFile } = await import('node:fs/promises');
      const { createOrUpdatePR } = await import('../src/github.js');

      const sharedAfter = '<pom><commons.version>1.10.0</commons.version></pom>';
      vi.mocked(runRemediation).mockResolvedValueOnce({
        exitCode: 0,
        remediations: [
          {
            purl: 'pkg:maven/org.apache.commons/commons-text@1.9',
            groupId: 'org.apache.commons',
            artifactId: 'commons-text',
            currentVersion: '1.9',
            fixedInVersion: '1.10.0',
            fixedInPurl: 'pkg:maven/org.apache.commons/commons-text@1.10.0',
            provider: 'osv',
            source: 'osv',
            severity: 'HIGH',
            cves: ['CVE-2022-42889'],
            advisories: [],
            files: ['pom.xml'],
            changes: [
              {
                path: 'pom.xml',
                after: sharedAfter,
                changeKey: 'mvn:prop:pom.xml:commons.version',
              },
            ],
          },
          {
            purl: 'pkg:maven/org.apache.commons/commons-lang3@3.11',
            groupId: 'org.apache.commons',
            artifactId: 'commons-lang3',
            currentVersion: '3.11',
            fixedInVersion: '1.10.0',
            fixedInPurl: 'pkg:maven/org.apache.commons/commons-lang3@1.10.0',
            provider: 'osv',
            source: 'osv',
            severity: 'MEDIUM',
            cves: ['CVE-2023-0002'],
            advisories: [],
            files: ['pom.xml'],
            changes: [
              {
                path: 'pom.xml',
                after: sharedAfter,
                changeKey: 'mvn:prop:pom.xml:commons.version',
              },
            ],
          },
        ],
      });

      const config: ActionConfig = {
        mode: 'remediate',
        dryRun: false,
        groupBy: 'dependency',
        branchPrefix: 'trustify-da',
        configPath: '.trustify-da.yml',
      };

      await runRemediateMode(config);

      // Same changeKey => one PR, one write
      expect(createOrUpdatePR).toHaveBeenCalledTimes(1);
      expect(writeFile).toHaveBeenCalledTimes(1);
      // remediation-count sums both deps' CVEs
      expect(core.setOutput).toHaveBeenCalledWith('remediation-count', 2);
    });
  });
});
