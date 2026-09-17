import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as core from '@actions/core';
import * as fs from 'fs/promises';
import { loadConfig } from '../src/config.js';

vi.mock('@actions/core');
vi.mock('fs/promises');

// loadConfig reads each field via core.getInput(name). Tests declare only the
// inputs they care about; everything else reads back as '' (the real getInput
// default for an unset input).
function mockInputs(inputs: Record<string, string>) {
  vi.mocked(core.getInput).mockImplementation((name: string) => inputs[name] ?? '');
}

// By default no config file exists on disk (readFile rejects). Individual tests
// override this to supply file contents.
function mockConfigFile(contents?: string) {
  if (contents === undefined) {
    vi.mocked(fs.readFile).mockRejectedValue(new Error('ENOENT'));
  } else {
    vi.mocked(fs.readFile).mockResolvedValue(contents);
  }
}

describe('loadConfig', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConfigFile(); // no file unless a test opts in
  });

  it('reads mode and applies defaults when only mode is given', async () => {
    mockInputs({ mode: 'remediate' });

    const config = await loadConfig();

    expect(config.mode).toBe('remediate');
    expect(config.dryRun).toBe(false);
    expect(config.labels).toEqual(['trustify-da']);
    expect(config.branchPrefix).toBe('trustify-da');
    expect(config.groupBy).toBe('bundle'); // empty input falls back to bundle
    expect(config.configPath).toBe('.trustify-da.yml');
  });

  it('splits and trims comma-separated list inputs', async () => {
    mockInputs({
      mode: 'remediate',
      providers: 'osv, snyk',
      sources: 'pom.xml, build.gradle',
      labels: 'security, deps',
      'sbom-targets': 'artifact, oci',
    });

    const config = await loadConfig();

    expect(config.providers).toEqual(['osv', 'snyk']);
    expect(config.sources).toEqual(['pom.xml', 'build.gradle']);
    expect(config.labels).toEqual(['security', 'deps']);
    expect(config.sbomTargets).toEqual(['artifact', 'oci']);
  });

  it('parses dry-run case-insensitively', async () => {
    mockInputs({ mode: 'check', 'dry-run': 'TRUE' });
    expect((await loadConfig()).dryRun).toBe(true);
  });

  it('warns and falls back to bundle for an invalid group-by', async () => {
    mockInputs({ mode: 'remediate', 'group-by': 'nonsense' });

    const config = await loadConfig();

    expect(config.groupBy).toBe('bundle');
    expect(core.warning).toHaveBeenCalled();
  });

  it('accepts a valid group-by unchanged', async () => {
    mockInputs({ mode: 'remediate', 'group-by': 'dependency' });

    const config = await loadConfig();

    expect(config.groupBy).toBe('dependency');
    expect(core.warning).not.toHaveBeenCalled();
  });

  it('lets action inputs override config-file values', async () => {
    mockConfigFile('backendUrl: https://from-file\nproviders:\n  - fileProvider\n');
    mockInputs({ mode: 'remediate', 'backend-url': 'https://from-input' });

    const config = await loadConfig();

    expect(config.backendUrl).toBe('https://from-input'); // input wins
    expect(config.providers).toEqual(['fileProvider']); // no input, file used
  });

  it('honors a custom config-path input', async () => {
    mockInputs({ mode: 'remediate', 'config-path': 'custom.yml' });

    const config = await loadConfig();

    expect(config.configPath).toBe('custom.yml');
    expect(fs.readFile).toHaveBeenCalledWith('custom.yml', 'utf-8');
  });

  it('tolerates a missing config file and logs an info message', async () => {
    mockInputs({ mode: 'remediate' });

    await expect(loadConfig()).resolves.toBeDefined();
    expect(core.info).toHaveBeenCalled();
  });
});
