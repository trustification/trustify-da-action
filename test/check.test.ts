import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as core from '@actions/core';
import { runCheckMode } from '../src/modes/check.js';
import type { ActionConfig } from '../src/config.js';

// @actions/core is mocked with a chainable summary so we can capture the markdown
// the mode writes to $GITHUB_STEP_SUMMARY without touching the filesystem.
vi.mock('@actions/core', () => {
  // Explicit type breaks the self-referential inference (addRaw returns summary).
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

// The JS client is mocked at the module boundary; each test configures the
// analysis report, remediations, and license data it needs.
vi.mock('@trustify-da/trustify-da-javascript-client/dist/src/index.js', () => ({
  default: { stackAnalysis: vi.fn() },
}));
vi.mock(
  '@trustify-da/trustify-da-javascript-client/dist/src/remediate.js',
  () => ({
    findManifests: vi.fn(),
  })
);
vi.mock(
  '@trustify-da/trustify-da-javascript-client/dist/src/remediation.js',
  () => ({
    extractRemediations: vi.fn(() => []),
  })
);
vi.mock(
  '@trustify-da/trustify-da-javascript-client/dist/src/license/index.js',
  () => ({
    licensesFromReport: vi.fn(() => new Map()),
    getCompatibility: vi.fn(() => 'unknown'),
    getProjectLicense: vi.fn(() => ({
      fromManifest: null,
      fromFile: null,
      mismatch: false,
    })),
  })
);

import daClient from '@trustify-da/trustify-da-javascript-client/dist/src/index.js';
import { findManifests } from '@trustify-da/trustify-da-javascript-client/dist/src/remediate.js';
import { extractRemediations } from '@trustify-da/trustify-da-javascript-client/dist/src/remediation.js';
import {
  licensesFromReport,
  getCompatibility,
  getProjectLicense,
} from '@trustify-da/trustify-da-javascript-client/dist/src/license/index.js';

const WORKSPACE = '/work';

/** Builds a check-mode ActionConfig, overriding only the fields a test cares about. */
function makeConfig(overrides: Partial<ActionConfig> = {}): ActionConfig {
  return {
    mode: 'check',
    backendUrl: 'https://trustify.test',
    dryRun: false,
    configPath: '.trustify-da.yml',
    ...overrides,
  };
}

/**
 * Describes one provider/source entry within a fake analysis report.
 *
 * A spec produces either a precomputed `summary` with the given severity counts
 * (the path the backend normally provides) or, when `issueSeverities` is set, a
 * summary-less source carrying a dependency whose issues have those raw severity
 * strings — the latter exercises the fallback counting path in `countSeverities`
 * that walks `dependencies[].issues[].severity`.
 */
interface SourceSpec {
  provider?: string;
  source?: string;
  severity?: { critical?: number; high?: number; medium?: number; low?: number };
  issueSeverities?: string[];
}

/** Builds the per-source report object (summary or dependency issues) for a spec. */
function buildSourceReport(spec: SourceSpec): unknown {
  return spec.issueSeverities
    ? {
        dependencies: [
          {
            issues: spec.issueSeverities.map((severity) => ({ severity })),
          },
        ],
      }
    : {
        summary: {
          critical: spec.severity?.critical ?? 0,
          high: spec.severity?.high ?? 0,
          medium: spec.severity?.medium ?? 0,
          low: spec.severity?.low ?? 0,
        },
      };
}

/**
 * Builds a minimal AnalysisReport.
 *
 * The single-source shorthand (`provider`/`source`/`severity`/`issueSeverities`)
 * covers most tests. For multi-provider/multi-source scenarios, pass `sources`
 * with one {@link SourceSpec} per entry; specs sharing a provider are grouped
 * under that provider, mirroring the real report shape.
 */
function makeReport(opts: {
  provider?: string;
  source?: string;
  scanned?: { total: number; direct: number; transitive: number };
  severity?: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
  };
  issueSeverities?: string[];
  sources?: SourceSpec[];
}): unknown {
  const specs: SourceSpec[] = opts.sources ?? [
    {
      provider: opts.provider,
      source: opts.source,
      severity: opts.severity,
      issueSeverities: opts.issueSeverities,
    },
  ];

  const providers: Record<string, { sources: Record<string, unknown> }> = {};
  for (const spec of specs) {
    const provider = spec.provider ?? 'osv';
    const source = spec.source ?? 'osv';
    (providers[provider] ??= { sources: {} }).sources[source] =
      buildSourceReport(spec);
  }

  return {
    scanned: opts.scanned ?? { total: 0, direct: 0, transitive: 0 },
    providers,
  };
}

/** Returns the concatenated markdown captured by the mocked summary.addRaw. */
function capturedSummary(): string {
  return vi
    .mocked(core.summary.addRaw)
    .mock.calls.map((call) => String(call[0]))
    .join('\n');
}

/** Returns the value passed to core.setOutput for the given output name. */
function outputValue(name: string): unknown {
  const call = vi
    .mocked(core.setOutput)
    .mock.calls.find(([outputName]) => outputName === name);
  return call?.[1];
}

describe('check mode', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = WORKSPACE;
    process.env.TRUSTIFY_DA_BACKEND_URL = 'https://trustify.test';
    // Restore default stubs cleared by clearAllMocks.
    vi.mocked(extractRemediations).mockReturnValue([]);
    vi.mocked(licensesFromReport).mockReturnValue(new Map());
    vi.mocked(getCompatibility).mockReturnValue('unknown');
    vi.mocked(getProjectLicense).mockReturnValue({
      fromManifest: null,
      fromFile: null,
      mismatch: false,
    } as never);
  });

  it('produces a markdown summary with the expected table structure', async () => {
    // Given a single manifest with a mix of severities and one remediation
    vi.mocked(findManifests).mockReturnValue([`${WORKSPACE}/pom.xml`]);
    vi.mocked(daClient.stackAnalysis).mockResolvedValue(
      makeReport({
        scanned: { total: 10, direct: 4, transitive: 6 },
        severity: { critical: 1, high: 2, medium: 0, low: 3 },
      }) as never
    );
    vi.mocked(extractRemediations).mockReturnValue([
      {
        purl: 'pkg:maven/com.example/vulnerable@1.0.0',
        groupId: 'com.example',
        artifactId: 'vulnerable',
        currentVersion: '1.0.0',
        fixedInVersion: '1.1.0',
        fixedInPurl: 'pkg:maven/com.example/vulnerable@1.1.0',
        provider: 'osv',
        source: 'osv',
        vulnerabilities: [
          { id: 'CVE-2024-1', severity: 'HIGH', advisories: [] },
        ],
      },
    ]);

    // When running check mode
    await runCheckMode(makeConfig());

    // Then the summary contains each section and correctly populated tables
    const md = capturedSummary();
    expect(md).toContain('# Trustify Dependency Analytics — Check Report');
    expect(md).toContain('## Dependencies Scanned');
    expect(md).toContain('| Total | 10 |');
    expect(md).toContain('| Direct | 4 |');
    expect(md).toContain('| Transitive | 6 |');
    expect(md).toContain('## Vulnerabilities');
    expect(md).toContain(
      '| Manifest | Provider | Source | Critical | High | Medium | Low |'
    );
    expect(md).toContain('| pom.xml | osv | osv | 1 | 2 | 0 | 3 |');
    expect(md).toContain('| **Total** | | | 1 | 2 | 0 | 3 |');
    expect(md).toContain('## Available Remediations');
    expect(md).toContain(
      '| com.example:vulnerable | 1.0.0 | 1.1.0 | osv | osv |'
    );
    // And the summary is flushed to $GITHUB_STEP_SUMMARY
    expect(core.summary.write).toHaveBeenCalledOnce();
  });

  it('sets structured outputs from the analysis results', async () => {
    // Given a manifest whose analysis yields specific severity and remediation data
    vi.mocked(findManifests).mockReturnValue([`${WORKSPACE}/pom.xml`]);
    vi.mocked(daClient.stackAnalysis).mockResolvedValue(
      makeReport({
        severity: { critical: 2, high: 3, medium: 1, low: 5 },
      }) as never
    );
    vi.mocked(extractRemediations).mockReturnValue([
      {
        purl: 'pkg:maven/com.example/a@1.0.0',
        groupId: 'com.example',
        artifactId: 'a',
        currentVersion: '1.0.0',
        fixedInVersion: '1.1.0',
        fixedInPurl: 'pkg:maven/com.example/a@1.1.0',
        provider: 'osv',
        source: 'osv',
        vulnerabilities: [
          { id: 'CVE-1', severity: 'HIGH', advisories: [] },
          { id: 'CVE-2', severity: 'LOW', advisories: [] },
        ],
      },
    ]);

    // When running check mode
    await runCheckMode(makeConfig());

    // Then each structured output reflects the aggregated counts
    expect(outputValue('critical-count')).toBe(2);
    expect(outputValue('high-count')).toBe(3);
    expect(outputValue('medium-count')).toBe(1);
    expect(outputValue('low-count')).toBe(5);
    // remediation-count sums the vulnerabilities carried by the remediations
    expect(outputValue('remediation-count')).toBe(2);
    expect(outputValue('license-conflicts')).toBe(0);
  });

  it('aggregates counts across multiple manifests', async () => {
    // Given two manifests each reporting vulnerabilities
    vi.mocked(findManifests).mockReturnValue([
      `${WORKSPACE}/pom.xml`,
      `${WORKSPACE}/sub/pom.xml`,
    ]);
    vi.mocked(daClient.stackAnalysis)
      .mockResolvedValueOnce(
        makeReport({
          scanned: { total: 5, direct: 2, transitive: 3 },
          severity: { critical: 1, high: 2, medium: 0, low: 1 },
        }) as never
      )
      .mockResolvedValueOnce(
        makeReport({
          scanned: { total: 7, direct: 3, transitive: 4 },
          severity: { critical: 1, high: 0, medium: 4, low: 2 },
        }) as never
      );

    // When running check mode
    await runCheckMode(makeConfig());

    // Then severity and scanned totals are summed across both manifests
    expect(outputValue('critical-count')).toBe(2);
    expect(outputValue('high-count')).toBe(2);
    expect(outputValue('medium-count')).toBe(4);
    expect(outputValue('low-count')).toBe(3);
    const md = capturedSummary();
    expect(md).toContain('| Total | 12 |');
    expect(md).toContain('| pom.xml | osv | osv | 1 | 2 | 0 | 1 |');
    expect(md).toContain('| sub/pom.xml | osv | osv | 1 | 0 | 4 | 2 |');
    expect(md).toContain('| **Total** | | | 2 | 2 | 4 | 3 |');
  });

  it('flags license conflicts and renders the license section', async () => {
    // Given a permissive project and a dependency with an incompatible license
    vi.mocked(findManifests).mockReturnValue([`${WORKSPACE}/pom.xml`]);
    vi.mocked(daClient.stackAnalysis).mockResolvedValue(
      makeReport({}) as never
    );
    vi.mocked(getProjectLicense).mockReturnValue({
      fromManifest: 'Apache-2.0',
      fromFile: null,
      mismatch: false,
    } as never);
    vi.mocked(licensesFromReport).mockReturnValue(
      new Map([
        [
          'pkg:maven/com.example/gpl-dep@1.0.0',
          { licenses: ['GPL-3.0'], category: 'STRONG_COPYLEFT' },
        ],
      ])
    );
    vi.mocked(getCompatibility).mockReturnValue('incompatible');

    // When running check mode
    await runCheckMode(makeConfig());

    // Then the license section and conflict are surfaced
    const md = capturedSummary();
    expect(md).toContain('## License Analysis');
    expect(md).toContain('| STRONG_COPYLEFT | 1 |');
    expect(md).toContain('### License Conflicts');
    expect(md).toContain('pkg:maven/com.example/gpl-dep@1.0.0');
    expect(outputValue('license-conflicts')).toBe(1);
  });

  it('omits the license section when no license data is available', async () => {
    // Given a manifest whose report carries no license data
    vi.mocked(findManifests).mockReturnValue([`${WORKSPACE}/pom.xml`]);
    vi.mocked(daClient.stackAnalysis).mockResolvedValue(
      makeReport({}) as never
    );
    vi.mocked(licensesFromReport).mockReturnValue(new Map());

    // When running check mode
    await runCheckMode(makeConfig());

    // Then no license section is rendered and no conflicts are reported
    const md = capturedSummary();
    expect(md).not.toContain('## License Analysis');
    expect(outputValue('license-conflicts')).toBe(0);
  });

  it('reports no vulnerabilities without a table when the scan is clean', async () => {
    // Given a manifest with zero findings
    vi.mocked(findManifests).mockReturnValue([`${WORKSPACE}/pom.xml`]);
    vi.mocked(daClient.stackAnalysis).mockResolvedValue(
      makeReport({}) as never
    );

    // When running check mode
    await runCheckMode(makeConfig());

    // Then the vulnerabilities section states none were found and counts are zero
    const md = capturedSummary();
    expect(md).toContain('No vulnerabilities found.');
    expect(outputValue('critical-count')).toBe(0);
    expect(outputValue('high-count')).toBe(0);
  });

  it('throws when no backend URL is configured', async () => {
    // Given no backend URL in config or environment
    delete process.env.TRUSTIFY_DA_BACKEND_URL;
    vi.mocked(findManifests).mockReturnValue([`${WORKSPACE}/pom.xml`]);

    // When/Then running check mode rejects with a helpful message
    await expect(
      runCheckMode(makeConfig({ backendUrl: undefined }))
    ).rejects.toThrow(/backend URL is required/i);
  });

  it('handles a workspace with no supported manifests', async () => {
    // Given no manifests discovered in the workspace
    vi.mocked(findManifests).mockReturnValue([]);

    // When running check mode
    await runCheckMode(makeConfig());

    // Then outputs are zeroed and analysis is never attempted
    expect(daClient.stackAnalysis).not.toHaveBeenCalled();
    expect(outputValue('critical-count')).toBe(0);
    expect(outputValue('remediation-count')).toBe(0);
  });

  it('merges counts across multiple providers and sources in one report', async () => {
    // Given a single manifest whose report has two providers, each with a source
    vi.mocked(findManifests).mockReturnValue([`${WORKSPACE}/pom.xml`]);
    vi.mocked(daClient.stackAnalysis).mockResolvedValue(
      makeReport({
        scanned: { total: 8, direct: 3, transitive: 5 },
        sources: [
          { provider: 'osv', source: 'osv', severity: { critical: 1, high: 2 } },
          { provider: 'snyk', source: 'snyk', severity: { high: 1, low: 4 } },
        ],
      }) as never
    );

    // When running check mode
    await runCheckMode(makeConfig());

    // Then each source renders its own row and totals sum across both
    const md = capturedSummary();
    expect(md).toContain('| pom.xml | osv | osv | 1 | 2 | 0 | 0 |');
    expect(md).toContain('| pom.xml | snyk | snyk | 0 | 1 | 0 | 4 |');
    expect(md).toContain('| **Total** | | | 1 | 3 | 0 | 4 |');
    expect(outputValue('critical-count')).toBe(1);
    expect(outputValue('high-count')).toBe(3);
    expect(outputValue('medium-count')).toBe(0);
    expect(outputValue('low-count')).toBe(4);
  });

  it('threads provider and source filters through to the analysis call', async () => {
    // Given a config that selects specific providers and sources
    vi.mocked(findManifests).mockReturnValue([`${WORKSPACE}/pom.xml`]);
    vi.mocked(daClient.stackAnalysis).mockResolvedValue(
      makeReport({}) as never
    );

    // When running check mode
    await runCheckMode(
      makeConfig({ providers: ['osv', 'snyk'], sources: ['pom.xml'] })
    );

    // Then stackAnalysis receives the manifest plus the backend/provider/source
    // options derived from the config
    expect(daClient.stackAnalysis).toHaveBeenCalledWith(
      `${WORKSPACE}/pom.xml`,
      false,
      expect.objectContaining({
        TRUSTIFY_DA_BACKEND_URL: 'https://trustify.test',
        TRUSTIFY_DA_PROVIDERS: 'osv,snyk',
        TRUSTIFY_DA_SOURCES: 'pom.xml',
      })
    );
  });

  it('wraps analysis failures with the offending manifest path', async () => {
    // Given the backend rejects the analysis of a manifest
    vi.mocked(findManifests).mockReturnValue([`${WORKSPACE}/sub/pom.xml`]);
    vi.mocked(daClient.stackAnalysis).mockRejectedValue(
      new Error('backend unreachable')
    );

    // When/Then check mode rejects with a message naming the manifest and cause
    await expect(runCheckMode(makeConfig())).rejects.toThrow(
      /Analysis failed for sub\/pom\.xml: backend unreachable/
    );
  });

  it('counts severities from dependency issues when no summary is present', async () => {
    // Given a source with no precomputed summary, only raw issue severities
    // (mixed case, plus an unrecognized value that must be ignored)
    vi.mocked(findManifests).mockReturnValue([`${WORKSPACE}/pom.xml`]);
    vi.mocked(daClient.stackAnalysis).mockResolvedValue(
      makeReport({
        issueSeverities: ['CRITICAL', 'high', 'Medium', 'LOW', 'low', 'bogus'],
      }) as never
    );

    // When running check mode
    await runCheckMode(makeConfig());

    // Then the fallback path counts case-insensitively and drops unknown values
    expect(outputValue('critical-count')).toBe(1);
    expect(outputValue('high-count')).toBe(1);
    expect(outputValue('medium-count')).toBe(1);
    expect(outputValue('low-count')).toBe(2);
  });

  it('skips license analysis without failing when it throws', async () => {
    // Given license extraction throws for a manifest
    vi.mocked(findManifests).mockReturnValue([`${WORKSPACE}/pom.xml`]);
    vi.mocked(daClient.stackAnalysis).mockResolvedValue(
      makeReport({ severity: { critical: 1 } }) as never
    );
    vi.mocked(licensesFromReport).mockImplementation(() => {
      throw new Error('license service down');
    });

    // When running check mode
    await runCheckMode(makeConfig());

    // Then it warns, omits the license section, and still reports vulnerabilities
    expect(core.warning).toHaveBeenCalledWith(
      expect.stringContaining('License analysis skipped')
    );
    const md = capturedSummary();
    expect(md).not.toContain('## License Analysis');
    expect(outputValue('license-conflicts')).toBe(0);
    expect(outputValue('critical-count')).toBe(1);
  });

  it('derives the project license category from its SPDX id', async () => {
    // Given an Apache-2.0 project and a strong-copyleft dependency
    vi.mocked(findManifests).mockReturnValue([`${WORKSPACE}/pom.xml`]);
    vi.mocked(daClient.stackAnalysis).mockResolvedValue(
      makeReport({}) as never
    );
    vi.mocked(getProjectLicense).mockReturnValue({
      fromManifest: 'Apache-2.0',
      fromFile: null,
      mismatch: false,
    } as never);
    vi.mocked(licensesFromReport).mockReturnValue(
      new Map([
        [
          'pkg:maven/com.example/gpl-dep@1.0.0',
          { licenses: ['GPL-3.0'], category: 'STRONG_COPYLEFT' },
        ],
      ])
    );
    vi.mocked(getCompatibility).mockReturnValue('incompatible');

    // When running check mode
    await runCheckMode(makeConfig());

    // Then Apache-2.0 is mapped to PERMISSIVE and used as the compatibility
    // baseline against the dependency's category
    expect(getCompatibility).toHaveBeenCalledWith(
      'PERMISSIVE',
      'STRONG_COPYLEFT'
    );
    expect(outputValue('license-conflicts')).toBe(1);
  });
});
