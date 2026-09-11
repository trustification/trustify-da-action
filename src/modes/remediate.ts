import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as github from '@actions/github';
import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { Remediation, runRemediation } from '@trustify-da/trustify-da-javascript-client/dist/src/remediate.js';
import { generateReport } from '@trustify-da/trustify-da-javascript-client/dist/src/remediation_report.js';
import type { ActionConfig } from '../config.js';
import { createOrUpdatePR } from '../github.js';

// A group is one PR. `branchName` and `title` are precomputed by the caller
// (bundle vs dependency), so the PR-creation path itself carries no mode
// conditionals. Bundle mode leaves `changes` undefined (the working tree already
// holds every fix); dependency mode carries the resolved per-path `after`
// content to write on its own branch.
interface PRGroup {
  key: string;
  branchName: string;
  title: string;
  remediations: Remediation[];
  changes?: Array<{ path: string; after: string }>;
  // The version actually written to the shared edit site for this group. When
  // deps collapse onto one Maven property, every dep is bumped to this single
  // value (the highest fix among them), which differs from each remediation's
  // own `fixedInVersion`. Undefined in bundle mode. Surfaced to the PR body so
  // it reflects the real on-disk change, not each dep's individual selection.
  appliedVersion?: string;
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
      throw new Error('GITHUB_TOKEN is required for PR creation. Set it via the token input or GITHUB_TOKEN env var.');
    }
  }

  const workspacePath = process.env.GITHUB_WORKSPACE || process.cwd();
  const groupBy: 'bundle' | 'dependency' = config.groupBy === 'dependency' ? 'dependency' : 'bundle';

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
    throw new Error(`Remediation failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  // Check exit code (0 = success, 2 = dry-run success)
  if (result.exitCode !== 0 && result.exitCode !== 2) {
    throw new Error(`Remediation failed with exit code ${result.exitCode}`);
  }

  const totalVulnerabilities = result.remediations.reduce(
    (sum, r) => sum + r.vulnerabilities.length,
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
    await runBundleMode(result.remediations, config, workspacePath);
  }
}

/**
 * Bundle mode: a single PR containing every fix already applied to the working tree.
 */
async function runBundleMode(
  remediations: Remediation[],
  config: ActionConfig,
  workspacePath: string
): Promise<void> {
  const changedFiles = await getChangedFiles(workspacePath);
  if (changedFiles.length === 0) {
    core.info('No files modified - no remediations applied');
    return;
  }

  core.info(`Modified files: ${changedFiles.join(', ')}`);
  core.setOutput('changed-files', changedFiles.join(','));

  const baseSha = await getHeadSha(workspacePath);
  const group: PRGroup = {
    key: 'bundle',
    branchName: `${config.branchPrefix}/remediate-vulnerabilities`,
    title: 'fix: remediate dependency vulnerabilities',
    remediations,
  };

  const prUrl = await createPRForGroup(
    group,
    config,
    changedFiles,
    workspacePath,
    baseSha
  );
  core.setOutput('pr-url', prUrl);
  core.info('Created 1 PR');
}

/**
 * Dependency mode: one PR per changeKey. Each PR's branch is pinned to the base
 * commit and receives only that dependency's `after` content, so fixes are never
 * lost when multiple dependencies share a manifest.
 */
async function runDependencyMode(
  remediations: Remediation[],
  config: ActionConfig,
  workspacePath: string
): Promise<void> {
  const rawGroups = groupByChangeKey(remediations);
  if (rawGroups.length === 0) {
    core.info('No per-dependency changes emitted - no remediations applied');
    return;
  }

  // The JS client applied every fix atomically to the working tree. We rebuild
  // each dependency's isolated change from its `after` content instead, so
  // discard the atomic working-tree edits to start each branch from a clean base.
  const allChangePaths = Array.from(
    new Set(rawGroups.flatMap((g) => g.changes.map((c) => c.path)))
  );
  core.setOutput('changed-files', allChangePaths.join(','));
  await discardWorkingTreeChanges(allChangePaths, workspacePath);

  // Pin every branch to this commit so each PR is isolated from the others,
  // regardless of whether the checkout left us on a branch or detached HEAD.
  const baseSha = await getHeadSha(workspacePath);

  core.info(`Creating ${rawGroups.length} PR(s) (groupBy: dependency)`);

  const purls: string[] = [];
  for (const raw of rawGroups) {
    // Readable dependency label (may be multiple deps when inseparable).
    const depLabel = Array.from(
      new Set(
        raw.remediations.map((r) =>
          r.groupId ? `${r.groupId}:${r.artifactId}` : r.artifactId
        )
      )
    ).join(', ');

    // Branch name: readable dep + short hash of the stable changeKey. The hash
    // keeps the name unique and bounded even for long keys/paths, while PR
    // updates still dedup to the same branch.
    const group: PRGroup = {
      key: raw.key,
      branchName: `${config.branchPrefix}/remediate-${sanitizeBranchName(depLabel)}-${shortHash(raw.key)}`,
      title: `fix: update ${depLabel} to fix vulnerabilities`,
      remediations: raw.remediations,
      changes: raw.changes,
      appliedVersion: raw.appliedVersion,
    };

    const prUrl = await createPRForGroup(
      group,
      config,
      raw.changes.map((c) => c.path),
      workspacePath,
      baseSha
    );
    purls.push(prUrl);
  }

  core.setOutput('pr-url', purls.length === 1 ? purls[0] : purls.join(','));
  core.info(`Created ${purls.length} PR(s)`);
}

/**
 * Groups remediations into PRs by the JS client's stable changeKey. Dependencies
 * that share an edit site (e.g. a shared Maven property or TOML version.ref)
 * collapse into one PR. On a version collision for the same changeKey+path
 * (same edit site, different fixed versions), the highest version wins.
 */
function groupByChangeKey(remediations: Remediation[]): Array<{
  key: string;
  remediations: Remediation[];
  changes: Array<{ path: string; after: string }>;
  appliedVersion: string;
}> {
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
        group = {
          key: change.changeKey,
          remediations: [],
          changeByPath: new Map(),
        };
        groups.set(change.changeKey, group);
      }
      if (!group.remediations.includes(remediation)) {
        group.remediations.push(remediation);
      }

      const existing = group.changeByPath.get(change.path);
      if (
        !existing ||
        compareVersions(remediation.fixedInVersion, existing.version) > 0
      ) {
        group.changeByPath.set(change.path, {
          after: change.after,
          version: remediation.fixedInVersion,
        });
      }
    }
  }

  return Array.from(groups.values()).map((group) => {
    const entries = Array.from(group.changeByPath.entries());
    // One changeKey maps to a single edit site, so the applied version is the
    // (highest) version written there — the value all deps in this group share.
    const appliedVersion = entries
      .map(([, value]) => value.version)
      .sort((a, b) => compareVersions(b, a))[0];
    return {
      key: group.key,
      remediations: group.remediations,
      appliedVersion,
      changes: entries.map(([path, value]) => ({ path, after: value.after })),
    };
  });
}

/**
 * Creates (or updates) the PR for a single group: materialize its changes, commit
 * and push its branch, then open/update the PR. All mode-specific naming is
 * already resolved on `group`.
 */
async function createPRForGroup(
  group: PRGroup,
  config: ActionConfig,
  changedFilesList: string[],
  workspacePath: string,
  baseSha: string
): Promise<string> {
  // Switch to a clean branch cut from the base commit BEFORE writing this group's
  // content. Materializing first would leave the previous group's branch dirty and
  // make `git checkout -B` abort ("local changes would be overwritten").
  await checkoutBranch(group.branchName, baseSha, workspacePath);
  await materializeChanges(group, workspacePath);
  await commitAndPushBranch(group, changedFilesList, workspacePath);

  core.info(`Creating or updating PR for branch: ${group.branchName}`);
  const prUrl = await createOrUpdatePR(
    {
      title: group.title,
      body: buildPrBody(group, config, changedFilesList),
      head: group.branchName,
      base: github.context.payload.repository?.default_branch ?? 'main',
      labels: config.labels,
    },
    {
      mode: 'remediate',
      groupBy: config.groupBy || 'bundle',
      dependency: group.key,
    }
  );

  core.info(`PR created/updated: ${prUrl}`);
  return prUrl;
}

/**
 * Writes each group change's isolated `after` content to disk. In bundle mode
 * `changes` is undefined and this is a no-op (the working tree already holds
 * every fix).
 */
async function materializeChanges(group: PRGroup, workspacePath: string): Promise<void> {
  for (const change of group.changes ?? []) {
    await writeFile(resolve(workspacePath, change.path), change.after);
  }
}

/**
 * Checks out `branchName` pinned to `baseSha`, creating or resetting it. Pinning
 * every group's branch to the base commit keeps each PR isolated from the
 * others' commits. Must run before materializing this group's content so the
 * previous group's working-tree edits never block the checkout.
 */
async function checkoutBranch(branchName: string, baseSha: string, workspacePath: string): Promise<void> {
  core.info(`Preparing branch: ${branchName}`);
  await exec.exec('git', ['checkout', '-B', branchName, baseSha], { cwd: workspacePath });
}

/**
 * Stages, commits, and pushes the listed files on the current branch.
 */
async function commitAndPushBranch(
  group: PRGroup,
  changedFilesList: string[],
  workspacePath: string
): Promise<void> {
  const options = { cwd: workspacePath };
  if (changedFilesList.length === 0) return;

  await exec.exec('git', ['add', ...changedFilesList], options);

  // Commit changes. Set the author inline (not via global config) so the action
  // works on bare CI runners that have no git identity configured.
  await exec.exec(
    'git',
    [
      '-c',
      'user.name=trustify-da[bot]',
      '-c',
      'user.email=trustify-da[bot]@users.noreply.github.com',
      'commit',
      '-m',
      group.title,
      '-m',
      'Automated remediation by Trustify Dependency Analytics',
    ],
    options
  );

  core.info(`Pushing branch: ${group.branchName}`);
  await pushBranch(group.branchName, workspacePath);
}

/**
 * Pushes the current branch to origin, overwriting any prior bot branch of the
 * same name. A bare `--force-with-lease` fails on fresh CI runners with "stale
 * info": with no remote-tracking ref for the branch, the lease has no known base
 * to compare against. So resolve the branch's current remote SHA via
 * `git ls-remote` and pin the lease to it — this still refuses to clobber a
 * concurrent push (the SHA won't match), but succeeds without a prior fetch.
 * When the branch does not exist remotely yet, a plain create is enough.
 */
async function pushBranch(branchName: string, workspacePath: string): Promise<void> {
  const options = { cwd: workspacePath };
  const lsRemote = await exec.getExecOutput(
    'git',
    ['ls-remote', '--heads', 'origin', branchName],
    options
  );
  const remoteSha = lsRemote.stdout.trim().split(/\s+/)[0] ?? '';

  const pushArgs = remoteSha
    ? ['push', 'origin', branchName, `--force-with-lease=${branchName}:${remoteSha}`]
    : ['push', '-u', 'origin', branchName];
  await exec.exec('git', pushArgs, options);
}

/**
 * Builds the PR body from the JS client report generator, using the actual
 * grouping mode so bundle PRs render a bundle report and dependency PRs a
 * dependency report.
 */
function buildPrBody(group: PRGroup, config: ActionConfig, changedFilesList: string[]): string {
  const groupBy = config.groupBy === 'dependency' ? 'dependency' : 'bundle';
  // Stamp each remediation with the group's applied version so the report reflects
  // the real on-disk change: the heading shows the applied version, and the client
  // derives its recommended-vs-applied divergence table straight from these entries
  // (a dep's own `fixedInVersion` vs the stamped `appliedVersion`). One PR body is
  // one collapsed group, so no extra grouping data is needed.
  const remediations = group.appliedVersion
    ? group.remediations.map((r) => ({ ...r, appliedVersion: group.appliedVersion }))
    : group.remediations;
  const report = generateReport(remediations, { groupBy });
  return `## Automated Dependency Remediation

${report}

### Changed Files
${changedFilesList.map((f) => `- \`${f}\``).join('\n')}

---
*Automated by [Trustify Dependency Analytics](https://github.com/trustification/trustify-da-action)*`;
}

/**
 * Short, stable hash of a changeKey for use as a branch-name suffix.
 */
function shortHash(value: string): string {
  return createHash('sha256').update(value).digest('hex').substring(0, 8);
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
 *
 * Edge case: splitting on `[.+-]` flattens pre-release/build separators, so a
 * release (`1.10.0`) can rank *below* its own pre-release (`1.10.0-rc1`) because
 * the extra `rc1` segment compares as greater than the release's implicit `0`.
 * This only affects tie-breaking between fixed versions that share a changeKey,
 * where remediations advertising a full release over a pre-release are expected;
 * revisit if the backend ever emits pre-release fixed versions.
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
async function discardWorkingTreeChanges(paths: string[], workspacePath: string): Promise<void> {
  if (paths.length === 0) return;
  await exec.exec('git', ['checkout', '--', ...paths], { cwd: workspacePath });
}

/**
 * Returns the current HEAD commit SHA.
 */
async function getHeadSha(workspacePath: string): Promise<string> {
  return (await exec.getExecOutput('git', ['rev-parse', 'HEAD'], { cwd: workspacePath })).stdout.trim();
}

/**
 * Gets list of modified files via git diff.
 */
async function getChangedFiles(workspacePath: string): Promise<string[]> {
  const output = (await exec.getExecOutput('git', ['diff', '--name-only'], { cwd: workspacePath })).stdout;

  return output
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}
