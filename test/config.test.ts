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

  it('exposes the remediation config object for downstream use', async () => {
    mockInputs({ mode: 'remediate' });
    const remediation = { labels: ['a'], 'branch-prefix': 'b/', exclude: ['pkg:maven/x/*'] };
    vi.mocked(resolveConfig).mockReturnValue(resolvedDefaults({ remediation }));

    const config = await loadConfig();

    expect(config.remediation).toEqual(remediation);
  });
});
