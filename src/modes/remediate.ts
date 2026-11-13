import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as github from '@actions/github';
import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { type RemediationGroup, runRemediation } from '@trustify-da/trustify-da-javascript-client/dist/src/remediate.js';
import { generateReport } from '@trustify-da/trustify-da-javascript-client/dist/src/remediation_report.js';
import type { ActionConfig } from '../config.js';
import { createOrUpdatePR } from '../github.js';

interface PRGroup {
  key: string;
  branchName: string;
  title: string;
  group: RemediationGroup;
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

  const backendUrl = config.backendUrl || process.env.TRUSTIFY_DA_BACKEND_URL;
  if (!backendUrl) {
    throw new Error(
      'A Trustify DA backend URL is required for remediation. Set it via the backend-url input, the backendUrl config, or the TRUSTIFY_DA_BACKEND_URL env var.'
    );
  }
  process.env.TRUSTIFY_DA_BACKEND_URL = backendUrl;

  core.info('Scanning manifests and extracting remediations...');
  let result: Awaited<ReturnType<typeof runRemediation>>;
  try {
    result = await runRemediation(workspacePath, {
      dryRun: config.dryRun,
      providers: config.providers.length > 0 ? config.providers.join(',') : undefined,
      sources: config.sources.length > 0 ? config.sources.join(',') : undefined,
      exclude: config.remediation?.exclude,
    });
  } catch (error) {
    throw new Error(`Remediation failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  if (result.exitCode !== 0 && result.exitCode !== 2) {
    throw new Error(`Remediation failed with exit code ${result.exitCode}`);
  }

  for (const s of result.skipped) {
    const name = s.groupId ? `${s.groupId}:${s.artifactId}` : s.artifactId;
    core.warning(`Skipped ${name}@${s.newVersion}: ${s.reason}`);
  }

  const totalVulnerabilities = result.remediations.reduce(
    (sum, r) => sum + r.vulnerabilities.length,
    0
  );
  core.setOutput('remediation-count', totalVulnerabilities);

  if (result.groups.length === 0) {
    core.info('No remediations found.');
    return;
  }

  const report = generateReport(result.remediations, { groupBy, groups: result.groups, skipped: result.skipped });
  core.info(report);

  if (config.dryRun) {
    core.info('Dry-run mode: skipping PR creation');
    return;
  }

  if (groupBy === 'dependency') {
    await runDependencyMode(result.groups, config, workspacePath, result.skipped);
  } else {
    await runBundleMode(result.groups, config, workspacePath, result.skipped);
  }
}

/**
 * Bundle mode: a single PR containing every fix already applied to the working tree.
 */
async function runBundleMode(
  groups: RemediationGroup[],
  config: ActionConfig,
  workspacePath: string,
  skipped: Array<{ groupId: string; artifactId: string; newVersion: string; reason: string }>
): Promise<void> {
  const changedFiles = await getChangedFiles(workspacePath);
  if (changedFiles.length === 0) {
    core.info('No files modified - no remediations applied');
    return;
  }

  core.info(`Modified files: ${changedFiles.join(', ')}`);
  core.setOutput('changed-files', changedFiles.join(','));

  const baseSha = await getHeadSha(workspacePath);
  const manifestLabel = changedFiles.join(', ');
  const remediations = groups.flatMap((g) => g.remediations);
  const prGroup: PRGroup = {
    key: 'bundle',
    branchName: `${config.branchPrefix}/remediate-vulnerabilities`,
    title: `fix: remediate dependency vulnerabilities in ${manifestLabel}`,
    group: groups[0],
  };

  const prUrl = await createPRForGroup(
    prGroup,
    remediations,
    groups,
    config,
    changedFiles,
    workspacePath,
    baseSha,
    skipped
  );
  core.setOutput('pr-url', prUrl);
  core.info('Created 1 PR');
}

/**
 * Dependency mode: one PR per group (edit site). Each PR's branch is pinned to the
 * base commit and receives only that group's `edit.after` content, so fixes are
 * never lost when multiple groups share a manifest.
 */
async function runDependencyMode(
  groups: RemediationGroup[],
  config: ActionConfig,
  workspacePath: string,
  skipped: Array<{ groupId: string; artifactId: string; newVersion: string; reason: string }>
): Promise<void> {
  if (groups.length === 0) {
    core.info('No per-dependency changes emitted - no remediations applied');
    return;
  }

  const allChangePaths = Array.from(
    new Set(groups.map((g) => g.edit.path))
  );
  core.setOutput('changed-files', allChangePaths.join(','));
  await discardWorkingTreeChanges(allChangePaths, workspacePath);

  const baseSha = await getHeadSha(workspacePath);

  core.info(`Creating ${groups.length} PR(s) (groupBy: dependency)`);

  const purls: string[] = [];
  for (const group of groups) {
    const depLabel = Array.from(
      new Set(
        group.remediations.map((r) =>
          r.groupId ? `${r.groupId}:${r.artifactId}` : r.artifactId
        )
      )
    ).join(', ');

    const prGroup: PRGroup = {
      key: group.changeKey,
      branchName: `${config.branchPrefix}/remediate-${sanitizeBranchName(depLabel)}-${shortHash(group.changeKey)}`,
      title: `fix: update ${depLabel} to fix vulnerabilities`,
      group,
    };

    const prUrl = await createPRForGroup(
      prGroup,
      group.remediations,
      [group],
      config,
      [group.edit.path],
      workspacePath,
      baseSha,
      skipped
    );
    purls.push(prUrl);
  }

  core.setOutput('pr-url', purls.length === 1 ? purls[0] : purls.join(','));
  core.info(`Created ${purls.length} PR(s)`);
}

/**
 * Creates (or updates) the PR for a single group: materialize its changes, commit
 * and push its branch, then open/update the PR.
 */
async function createPRForGroup(
  prGroup: PRGroup,
  remediations: RemediationGroup['remediations'],
  groups: RemediationGroup[],
  config: ActionConfig,
  changedFilesList: string[],
  workspacePath: string,
  baseSha: string,
  skipped: Array<{ groupId: string; artifactId: string; newVersion: string; reason: string }>
): Promise<string> {
  await checkoutBranch(prGroup.branchName, baseSha, workspacePath);
  await materializeEdit(prGroup, workspacePath);
  await commitAndPushBranch(prGroup, changedFilesList, workspacePath);

  core.info(`Creating or updating PR for branch: ${prGroup.branchName}`);
  const prUrl = await createOrUpdatePR(
    {
      title: prGroup.title,
      body: buildPrBody(remediations, groups, config, changedFilesList, skipped),
      head: prGroup.branchName,
      base: github.context.payload.repository?.default_branch ?? 'main',
      labels: config.labels,
    },
    {
      mode: 'remediate',
      branch: prGroup.branchName,
    }
  );

  core.info(`PR created/updated: ${prUrl}`);
  return prUrl;
}

/**
 * Writes the group's isolated `edit.after` content to disk. In bundle mode the
 * working tree already holds every fix, so this is a no-op (bundle PRGroups carry
 * no edit that needs materializing since the orchestrator already wrote the combined
 * content).
 */
async function materializeEdit(prGroup: PRGroup, workspacePath: string): Promise<void> {
  if (prGroup.key === 'bundle') return;
  const { path, after } = prGroup.group.edit;
  await writeFile(resolve(workspacePath, path), after);
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
  prGroup: PRGroup,
  changedFilesList: string[],
  workspacePath: string
): Promise<void> {
  const options = { cwd: workspacePath };
  if (changedFilesList.length === 0) return;

  await exec.exec('git', ['add', ...changedFilesList], options);

  await exec.exec(
    'git',
    [
      '-c',
      'user.name=trustify-da[bot]',
      '-c',
      'user.email=trustify-da[bot]@users.noreply.github.com',
      'commit',
      '-m',
      prGroup.title,
      '-m',
      'Automated remediation by Trustify Dependency Analytics',
    ],
    options
  );

  core.info(`Pushing branch: ${prGroup.branchName}`);
  await pushBranch(prGroup.branchName, workspacePath);
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
 * Builds the PR body: the report generator handles all remediation-specific content
 * (including divergence and skipped sections), the action adds GH-specific sections.
 */
function buildPrBody(
  remediations: RemediationGroup['remediations'],
  groups: RemediationGroup[],
  config: ActionConfig,
  changedFilesList: string[],
  skipped: Array<{ groupId: string; artifactId: string; newVersion: string; reason: string }>
): string {
  const groupBy = config.groupBy === 'dependency' ? 'dependency' : 'bundle';
  const report = generateReport(remediations, { groupBy, groups, skipped });

  return `## Automated Dependency Remediation

${report}

### Changed Files
${changedFilesList.map((f) => `- \`${f}\``).join('\n')}

---
*Automated by [Trustify Dependency Analytics](https://github.com/trustification/trustify-da-action)*`;
}

function shortHash(value: string): string {
  return createHash('sha256').update(value).digest('hex').substring(0, 8);
}

function sanitizeBranchName(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9-_.]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

async function discardWorkingTreeChanges(paths: string[], workspacePath: string): Promise<void> {
  if (paths.length === 0) return;
  await exec.exec('git', ['checkout', '--', ...paths], { cwd: workspacePath });
}

async function getHeadSha(workspacePath: string): Promise<string> {
  return (await exec.getExecOutput('git', ['rev-parse', 'HEAD'], { cwd: workspacePath })).stdout.trim();
}

async function getChangedFiles(workspacePath: string): Promise<string[]> {
  const output = (await exec.getExecOutput('git', ['diff', '--name-only'], { cwd: workspacePath })).stdout;

  return output
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}
