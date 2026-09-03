import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { runRemediation } from '@trustify-da/trustify-da-javascript-client/dist/src/remediate.js';
import { generateReport } from '@trustify-da/trustify-da-javascript-client/dist/src/remediation_report.js';
import type { ActionConfig } from '../config.js';
import { createOrUpdatePR } from '../github.js';

interface Change {
  path: string;
  after: string;
  changeKey: string;
}

interface Remediation {
  purl: string;
  groupId: string;
  artifactId: string;
  currentVersion: string;
  fixedInVersion: string;
  fixedInPurl: string;
  provider: string;
  source: string;
  severity: string;
  cves: string[];
  advisories: Array<{ id: string; url: string }>;
  files: string[];
  changes?: Change[];
}

// A group is one PR. In bundle mode there is a single group with no `changes`
// (the working tree already holds every fix). In dependency mode each group is
// keyed by the JS client's stable changeKey and carries the resolved per-path
// `after` content to write on its own branch.
interface PRGroup {
  key: string;
  remediations: Remediation[];
  changes?: Array<{ path: string; after: string }>;
}

/**
 * Runs the remediate mode: analyzes dependencies, creates/updates PRs with fixes.
 */
export async function runRemediateMode(config: ActionConfig): Promise<void> {
  core.info('Running in remediate mode');

  // Validate GITHUB_TOKEN early to avoid orphaned branches
  if (!config.dryRun) {
    const token = core.getInput('token') || process.env.GITHUB_TOKEN;
    if (!token) {
      throw new Error(
        'GITHUB_TOKEN is required for PR creation. Set it via the token input or GITHUB_TOKEN env var.'
      );
    }
  }

  const workspacePath = process.env.GITHUB_WORKSPACE || process.cwd();
  const groupBy: 'bundle' | 'dependency' =
    config.groupBy === 'dependency' ? 'dependency' : 'bundle';

  // The JS client discovers the DA backend via the TRUSTIFY_DA_BACKEND_URL env
  // var (selectTrustifyDABackend throws if unset). Thread the action's
  // backend-url input through so remediation can reach the backend.
  const backendUrl = config.backendUrl || process.env.TRUSTIFY_DA_BACKEND_URL;
  if (!backendUrl) {
    throw new Error(
      'A Trustify DA backend URL is required for remediation. Set it via the backend-url input, the backendUrl config, or the TRUSTIFY_DA_BACKEND_URL env var.'
    );
  }
  process.env.TRUSTIFY_DA_BACKEND_URL = backendUrl;

  // Run remediation via JS client with error handling
  core.info('Scanning manifests and extracting remediations...');
  let result: { exitCode: number; remediations: Remediation[] };
  try {
    result = await runRemediation(workspacePath, {
      dryRun: config.dryRun,
      providers: config.providers?.join(','),
      sources: config.sources?.join(','),
      // Opt into per-dependency change data only when we need isolated PRs.
      perDependencyChanges: groupBy === 'dependency',
    });
  } catch (error) {
    throw new Error(
      `Remediation failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  // Check exit code (0 = success, 2 = dry-run success)
  if (result.exitCode !== 0 && result.exitCode !== 2) {
    throw new Error(`Remediation failed with exit code ${result.exitCode}`);
  }

  const totalVulnerabilities = result.remediations.reduce(
    (sum, r) => sum + r.cves.length,
    0
  );
  core.setOutput('remediation-count', totalVulnerabilities);

  if (result.remediations.length === 0) {
    core.info('No remediations found.');
    return;
  }

  // Generate and log report
  const report = generateReport(result.remediations, { groupBy });
  core.info(report);

  if (config.dryRun) {
    core.info('Dry-run mode: skipping PR creation');
    return;
  }

  if (groupBy === 'dependency') {
    await runDependencyMode(result.remediations, config, workspacePath);
  } else {
    await runBundleMode(result.remediations, config);
  }
}

/**
 * Bundle mode: a single PR containing every fix already applied to the working tree.
 */
async function runBundleMode(
  remediations: Remediation[],
  config: ActionConfig
): Promise<void> {
  const changedFiles = await getChangedFiles();
  if (changedFiles.length === 0) {
    core.info('No files modified - no remediations applied');
    return;
  }

  core.info(`Modified files: ${changedFiles.join(', ')}`);
  core.setOutput('changed-files', changedFiles.join(','));

  const prUrl = await createPRForGroup(
    { key: 'bundle', remediations },
    config,
    changedFiles
  );
  core.setOutput('pr-url', prUrl);
  core.info('Created 1 PR');
}

/**
 * Dependency mode: one PR per changeKey. Each PR's branch is built from base and
 * receives only that dependency's `after` content, so fixes are never lost when
 * multiple dependencies share a manifest.
 */
async function runDependencyMode(
  remediations: Remediation[],
  config: ActionConfig,
  workspacePath: string
): Promise<void> {
  const groups = groupByChangeKey(remediations);
  if (groups.length === 0) {
    core.info('No per-dependency changes emitted - no remediations applied');
    return;
  }

  // The JS client applied every fix atomically to the working tree. We rebuild
  // each dependency's isolated change from its `after` content instead, so
  // discard the atomic working-tree edits to start each branch from a clean base.
  const allChangePaths = Array.from(
    new Set(groups.flatMap((g) => g.changes!.map((c) => c.path)))
  );
  core.setOutput('changed-files', allChangePaths.join(','));
  await discardWorkingTreeChanges(allChangePaths);

  core.info(`Creating ${groups.length} PR(s) (groupBy: dependency)`);

  const prUrls: string[] = [];
  for (const group of groups) {
    const prUrl = await createPRForGroup(group, config, group.changes!.map((c) => c.path), workspacePath);
    prUrls.push(prUrl);
  }

  core.setOutput('pr-url', prUrls.length === 1 ? prUrls[0] : prUrls.join(','));
  core.info(`Created ${prUrls.length} PR(s)`);
}

/**
 * Groups remediations into PRs by the JS client's stable changeKey. Dependencies
 * that share an edit site (e.g. a shared Maven property or TOML version.ref)
 * collapse into one PR. On a version collision for the same changeKey+path
 * (same edit site, different fixed versions), the highest version wins.
 */
function groupByChangeKey(remediations: Remediation[]): PRGroup[] {
  const groups = new Map<
    string,
    {
      key: string;
      remediations: Remediation[];
      changeByPath: Map<string, { after: string; version: string }>;
    }
  >();

  for (const remediation of remediations) {
    for (const change of remediation.changes ?? []) {
      let group = groups.get(change.changeKey);
      if (!group) {
        group = { key: change.changeKey, remediations: [], changeByPath: new Map() };
        groups.set(change.changeKey, group);
      }
      if (!group.remediations.includes(remediation)) {
        group.remediations.push(remediation);
      }

      const existing = group.changeByPath.get(change.path);
      if (!existing || compareVersions(remediation.fixedInVersion, existing.version) > 0) {
        group.changeByPath.set(change.path, {
          after: change.after,
          version: remediation.fixedInVersion,
        });
      }
    }
  }

  return Array.from(groups.values()).map((group) => ({
    key: group.key,
    remediations: group.remediations,
    changes: Array.from(group.changeByPath.entries()).map(([path, value]) => ({
      path,
      after: value.after,
    })),
  }));
}

/**
 * Creates a PR for a group of remediations.
 */
async function createPRForGroup(
  group: PRGroup,
  config: ActionConfig,
  changedFilesList: string[],
  workspacePath?: string
): Promise<string> {
  const branchPrefix = config.branchPrefix || 'trustify-da';
  const isBundled = group.key === 'bundle';

  // Branch name: bundle mode uses a generic name; per-dependency uses the
  // sanitized (stable) changeKey so PR updates dedup to the same branch.
  const branchSuffix = isBundled
    ? 'remediate-vulnerabilities'
    : `remediate-${sanitizeBranchName(group.key)}`;
  const branchName = `${branchPrefix}/${branchSuffix}`;

  // Readable dependency label for title (may be multiple when inseparable).
  const depLabel = Array.from(
    new Set(
      group.remediations.map((r) =>
        r.groupId ? `${r.groupId}:${r.artifactId}` : r.artifactId
      )
    )
  ).join(', ');

  const prTitle = isBundled
    ? 'fix: remediate dependency vulnerabilities'
    : `fix: update ${depLabel} to fix vulnerabilities`;

  // PR body from JS client report generator
  const report = generateReport(group.remediations, { groupBy: 'dependency' });
  const prBody = `## Automated Dependency Remediation

${report}

### Changed Files
${changedFilesList.map((f) => `- \`${f}\``).join('\n')}

---
*Automated by [Trustify Dependency Analytics](https://github.com/trustification/trustify-da-action)*`;

  core.info(`Preparing branch: ${branchName}`);

  // Save current branch
  let currentBranch = '';
  await exec.exec('git', ['branch', '--show-current'], {
    listeners: {
      stdout: (data: Buffer) => {
        currentBranch += data.toString().trim();
      },
    },
  });

  try {
    // Check if branch already exists locally
    try {
      await exec.exec('git', ['rev-parse', '--verify', branchName], {
        ignoreReturnCode: true,
      });
      core.info(`Branch ${branchName} exists, switching to it`);
      await exec.exec('git', ['checkout', branchName]);
    } catch {
      core.info(`Creating new branch: ${branchName}`);
      await exec.exec('git', ['checkout', '-b', branchName]);
    }

    // In dependency mode, materialize this group's isolated `after` content.
    // In bundle mode the working tree already holds every fix.
    if (!isBundled && group.changes) {
      for (const change of group.changes) {
        const target = workspacePath ? resolve(workspacePath, change.path) : change.path;
        await writeFile(target, change.after);
      }
    }

    // Stage files for this group
    if (changedFilesList.length > 0) {
      await exec.exec('git', ['add', ...changedFilesList]);

      // Commit changes. Set the author inline (not via global config) so the
      // action works on bare CI runners that have no git identity configured.
      await exec.exec('git', [
        '-c',
        'user.name=trustify-da[bot]',
        '-c',
        'user.email=trustify-da[bot]@users.noreply.github.com',
        'commit',
        '-m',
        prTitle,
        '-m',
        'Automated remediation by Trustify Dependency Analytics',
      ]);

      // Push branch with --force-with-lease for safety
      core.info(`Pushing branch: ${branchName}`);
      await exec.exec('git', ['push', '-u', 'origin', branchName, '--force-with-lease']);
    }

    // Create or update PR with dedupContext
    core.info(`Creating or updating PR for branch: ${branchName}`);

    const prUrl = await createOrUpdatePR(
      {
        title: prTitle,
        body: prBody,
        head: branchName,
        base: 'main',
        labels: config.labels || ['trustify-da', 'security'],
      },
      {
        mode: 'remediate',
        groupBy: config.groupBy || 'bundle',
        dependency: group.key,
      }
    );

    core.info(`PR created/updated: ${prUrl}`);
    return prUrl;
  } finally {
    // Return to original branch
    if (currentBranch && currentBranch !== branchName) {
      await exec.exec('git', ['checkout', currentBranch]);
    }
  }
}

/**
 * Sanitizes a dependency name for use in git branch names.
 */
function sanitizeBranchName(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9-_.]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

/**
 * Compares two dotted version strings numerically. Returns >0 if a > b, <0 if
 * a < b, 0 if equal. Non-numeric segments compare lexically as a fallback.
 */
function compareVersions(a: string, b: string): number {
  const aParts = a.split(/[.+-]/);
  const bParts = b.split(/[.+-]/);
  const len = Math.max(aParts.length, bParts.length);

  for (let i = 0; i < len; i++) {
    const aRaw = aParts[i] ?? '0';
    const bRaw = bParts[i] ?? '0';
    const aNum = Number(aRaw);
    const bNum = Number(bRaw);

    if (!Number.isNaN(aNum) && !Number.isNaN(bNum)) {
      if (aNum !== bNum) return aNum - bNum;
    } else if (aRaw !== bRaw) {
      return aRaw < bRaw ? -1 : 1;
    }
  }

  return 0;
}

/**
 * Discards unstaged working-tree edits for the given paths, restoring them to HEAD.
 */
async function discardWorkingTreeChanges(paths: string[]): Promise<void> {
  if (paths.length === 0) return;
  await exec.exec('git', ['checkout', '--', ...paths]);
}

/**
 * Gets list of modified files via git diff.
 */
async function getChangedFiles(): Promise<string[]> {
  let output = '';

  await exec.exec('git', ['diff', '--name-only'], {
    listeners: {
      stdout: (data: Buffer) => {
        output += data.toString();
      },
    },
  });

  return output
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}
