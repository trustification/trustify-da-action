import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as core from '@actions/core';
import { loadConfig } from '../src/config.js';

vi.mock('@actions/core');
vi.mock('@trustify-da/trustify-da-javascript-client/dist/src/config.js', () => ({
  resolveConfig: vi.fn(),
}));

import { resolveConfig } from '@trustify-da/trustify-da-javascript-client/dist/src/config.js';

function mockInputs(inputs: Record<string, string>) {
  vi.mocked(core.getInput).mockImplementation((name: string) => inputs[name] ?? '');
}

/** Returns a ResolvedConfig-shaped object with sensible defaults. */
function resolvedDefaults(overrides: Record<string, unknown> = {}) {
  return {
    backendUrl: null,
    backendUrlSource: 'default' as const,
    providers: [] as string[],
    sources: [] as string[],
    groupBy: 'dependency',
    remediation: {},
    check: {},
    sbom: {},
    ...overrides,
  };
}

describe('loadConfig', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(resolveConfig).mockReturnValue(resolvedDefaults());
  });

  it('reads mode and applies defaults when only mode is given', async () => {
    mockInputs({ mode: 'remediate' });

    const config = await loadConfig();

    expect(config.mode).toBe('remediate');
    expect(config.dryRun).toBe(false);
    expect(config.labels).toEqual(['trustify-da']);
    expect(config.branchPrefix).toBe('trustify-da');
    expect(config.groupBy).toBe('dependency');
  });

  it('passes action inputs as cliFlags to resolveConfig', async () => {
    mockInputs({
      mode: 'remediate',
      'backend-url': 'https://from-input',
      providers: 'osv,snyk',
      sources: 'pom.xml',
      'group-by': 'dependency',
    });
    vi.mocked(resolveConfig).mockReturnValue(
      resolvedDefaults({
        backendUrl: 'https://from-input',
        providers: ['osv', 'snyk'],
        sources: ['pom.xml'],
        groupBy: 'dependency',
      }),
    );

    const config = await loadConfig('/workspace');

    expect(resolveConfig).toHaveBeenCalledWith(
      '/workspace',
      {
        backendUrl: 'https://from-input',
        providers: 'osv,snyk',
        sources: 'pom.xml',
        groupBy: 'dependency',
      },
      expect.any(Object),
    );
    expect(config.backendUrl).toBe('https://from-input');
    expect(config.providers).toEqual(['osv', 'snyk']);
    expect(config.sources).toEqual(['pom.xml']);
    expect(config.groupBy).toBe('dependency');
  });

  it('parses dry-run case-insensitively', async () => {
    mockInputs({ mode: 'check', 'dry-run': 'TRUE' });
    expect((await loadConfig()).dryRun).toBe(true);
  });

  it('warns and falls back to dependency for an invalid group-by', async () => {
    mockInputs({ mode: 'remediate', 'group-by': 'nonsense' });
    vi.mocked(resolveConfig).mockReturnValue(resolvedDefaults({ groupBy: 'nonsense' }));

    const config = await loadConfig();

    expect(config.groupBy).toBe('dependency');
    expect(core.warning).toHaveBeenCalled();
  });

  it('accepts a valid group-by unchanged', async () => {
    mockInputs({ mode: 'remediate', 'group-by': 'dependency' });
    vi.mocked(resolveConfig).mockReturnValue(resolvedDefaults({ groupBy: 'dependency' }));

    const config = await loadConfig();

    expect(config.groupBy).toBe('dependency');
    expect(core.warning).not.toHaveBeenCalled();
  });

  it('uses GITHUB_WORKSPACE as default discovery path', async () => {
    process.env.GITHUB_WORKSPACE = '/actions/workspace';
    mockInputs({ mode: 'remediate' });

    await loadConfig();

    expect(resolveConfig).toHaveBeenCalledWith(
      '/actions/workspace',
      expect.any(Object),
      expect.any(Object),
    );
    delete process.env.GITHUB_WORKSPACE;
  });

  it('splits and trims sbom-targets', async () => {
    mockInputs({ mode: 'sbom', 'sbom-targets': 'artifact, oci' });

    const config = await loadConfig();

    expect(config.sbomTargets).toEqual(['artifact', 'oci']);
  });

  describe('labels merging', () => {
    it('merges action input labels with remediation.labels from config', async () => {
      mockInputs({ mode: 'remediate', labels: 'security,deps' });
      vi.mocked(resolveConfig).mockReturnValue(
        resolvedDefaults({ remediation: { labels: ['auto-fix', 'deps'] } }),
      );

      const config = await loadConfig();

      expect(config.labels).toEqual(['security', 'deps', 'auto-fix']);
    });

    it('uses remediation.labels from config when no action input', async () => {
      mockInputs({ mode: 'remediate' });
      vi.mocked(resolveConfig).mockReturnValue(
        resolvedDefaults({ remediation: { labels: ['from-config'] } }),
      );

      const config = await loadConfig();

      expect(config.labels).toEqual(['from-config']);
    });

    it('trims whitespace from comma-separated label input', async () => {
      mockInputs({ mode: 'remediate', labels: ' security , deps ' });

      const config = await loadConfig();

      expect(config.labels).toEqual(['security', 'deps']);
    });

    it('defaults to ["trustify-da"] when neither source provides labels', async () => {
      mockInputs({ mode: 'remediate' });

      const config = await loadConfig();

      expect(config.labels).toEqual(['trustify-da']);
    });
  });

  describe('branch prefix', () => {
    it('uses action input over config file', async () => {
      mockInputs({ mode: 'remediate', 'branch-prefix': 'my-prefix' });
      vi.mocked(resolveConfig).mockReturnValue(
        resolvedDefaults({ remediation: { 'branch-prefix': 'from-config/' } }),
      );

      const config = await loadConfig();

      expect(config.branchPrefix).toBe('my-prefix');
    });

    it('uses remediation.branch-prefix from config when no action input', async () => {
      mockInputs({ mode: 'remediate' });
      vi.mocked(resolveConfig).mockReturnValue(
        resolvedDefaults({ remediation: { 'branch-prefix': 'da-fix/' } }),
      );

      const config = await loadConfig();

      expect(config.branchPrefix).toBe('da-fix');
    });

    it('strips trailing slashes from branch prefix', async () => {
      mockInputs({ mode: 'remediate', 'branch-prefix': 'prefix///' });

      const config = await loadConfig();

      expect(config.branchPrefix).toBe('prefix');
    });

    it('defaults to trustify-da when absent everywhere', async () => {
      mockInputs({ mode: 'remediate' });

      const config = await loadConfig();

      expect(config.branchPrefix).toBe('trustify-da');
    });
  });

  describe('backend-url from config', () => {
    it('action input overrides config file value', async () => {
      mockInputs({ mode: 'remediate', 'backend-url': 'https://from-input' });
      vi.mocked(resolveConfig).mockReturnValue(
        resolvedDefaults({ backendUrl: 'https://from-input' }),
      );

      const config = await loadConfig();

      expect(config.backendUrl).toBe('https://from-input');
    });

    it('uses config file value when action input is absent', async () => {
      mockInputs({ mode: 'remediate' });
      vi.mocked(resolveConfig).mockReturnValue(
        resolvedDefaults({ backendUrl: 'https://from-file' }),
      );

      const config = await loadConfig();

      expect(config.backendUrl).toBe('https://from-file');
    });
  });

  it('absent config file produces no error — defaults apply', async () => {
    mockInputs({ mode: 'remediate' });
    // resolveConfig handles missing files gracefully (returns defaults)
    vi.mocked(resolveConfig).mockReturnValue(resolvedDefaults());

    await expect(loadConfig()).resolves.toBeDefined();
  });

  describe('fail-on thresholds', () => {
    it('parses integer threshold from action input', async () => {
      mockInputs({ mode: 'check', 'fail-on-critical': '5' });

      const config = await loadConfig();

      expect(config.failOn.critical).toBe(5);
    });

    it('treats "true" as threshold 0 (fail on any)', async () => {
      mockInputs({ mode: 'check', 'fail-on-critical': 'true' });

      const config = await loadConfig();

      expect(config.failOn.critical).toBe(0);
    });

    it('treats "false" as undefined (no gate)', async () => {
      mockInputs({ mode: 'check', 'fail-on-critical': 'false' });

      const config = await loadConfig();

      expect(config.failOn.critical).toBeUndefined();
    });

    it('treats threshold 0 as a valid value (not as unset)', async () => {
      mockInputs({ mode: 'check', 'fail-on-high': '0' });

      const config = await loadConfig();

      expect(config.failOn.high).toBe(0);
    });

    it('falls back to config file threshold when action input is absent', async () => {
      mockInputs({ mode: 'check' });
      vi.mocked(resolveConfig).mockReturnValue(
        resolvedDefaults({ check: { 'fail-on': { critical: 3 } } }),
      );

      const config = await loadConfig();

      expect(config.failOn.critical).toBe(3);
    });

    it('action input threshold overrides config file threshold', async () => {
      mockInputs({ mode: 'check', 'fail-on-critical': '1' });
      vi.mocked(resolveConfig).mockReturnValue(
        resolvedDefaults({ check: { 'fail-on': { critical: 10 } } }),
      );

      const config = await loadConfig();

      expect(config.failOn.critical).toBe(1);
    });

    it('parses license-conflicts threshold', async () => {
      mockInputs({ mode: 'check', 'fail-on-license-conflicts': '2' });

      const config = await loadConfig();

      expect(config.failOn.licenseConflicts).toBe(2);
    });

    it('falls back to config file license-conflicts threshold', async () => {
      mockInputs({ mode: 'check' });
      vi.mocked(resolveConfig).mockReturnValue(
        resolvedDefaults({ check: { 'fail-on': { 'license-conflicts': 0 } } }),
      );

      const config = await loadConfig();

      expect(config.failOn.licenseConflicts).toBe(0);
    });

    it('"false" input overrides config file threshold (disables gate)', async () => {
      mockInputs({ mode: 'check', 'fail-on-critical': 'false' });
      vi.mocked(resolveConfig).mockReturnValue(
        resolvedDefaults({ check: { 'fail-on': { critical: 0 } } }),
      );

      const config = await loadConfig();

      expect(config.failOn.critical).toBeUndefined();
    });

    it('leaves thresholds undefined when absent from both input and config', async () => {
      mockInputs({ mode: 'check' });

      const config = await loadConfig();

      expect(config.failOn.critical).toBeUndefined();
      expect(config.failOn.high).toBeUndefined();
      expect(config.failOn.licenseConflicts).toBeUndefined();
    });

    it('warns on invalid threshold value and treats as undefined', async () => {
      mockInputs({ mode: 'check', 'fail-on-critical': 'banana' });

      const config = await loadConfig();

      expect(config.failOn.critical).toBeUndefined();
      expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('Invalid threshold'));
    });

    it('rejects "0.5" as a threshold (parseInt truncation guard)', async () => {
      mockInputs({ mode: 'check', 'fail-on-critical': '0.5' });

      const config = await loadConfig();

      expect(config.failOn.critical).toBeUndefined();
      expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('Invalid threshold'));
    });

    it('rejects "1e3" as a threshold (parseInt truncation guard)', async () => {
      mockInputs({ mode: 'check', 'fail-on-critical': '1e3' });

      const config = await loadConfig();

      expect(config.failOn.critical).toBeUndefined();
      expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('Invalid threshold'));
    });

    it('rejects "3abc" as a threshold (parseInt truncation guard)', async () => {
      mockInputs({ mode: 'check', 'fail-on-critical': '3abc' });

      const config = await loadConfig();

      expect(config.failOn.critical).toBeUndefined();
      expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('Invalid threshold'));
    });
  });

  it('exposes the remediation config object for downstream use', async () => {
    mockInputs({ mode: 'remediate' });
    const remediation = { labels: ['a'], 'branch-prefix': 'b/', exclude: ['pkg:maven/x/*'] };
    vi.mocked(resolveConfig).mockReturnValue(resolvedDefaults({ remediation }));

    const config = await loadConfig();

    expect(config.remediation).toEqual(remediation);
  });
});
