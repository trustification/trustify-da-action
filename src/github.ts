import * as github from '@actions/github';
import * as core from '@actions/core';
import crypto from 'crypto';

/**
 * Generates a deduplication key from context data.
 */
function generateDeduplicationKey(context: Record<string, unknown>): string {
  const normalized = JSON.stringify(context, Object.keys(context).sort());
  return crypto.createHash('sha256').update(normalized).digest('hex').substring(0, 16);
}

export interface PROptions {
  title: string;
  body: string;
  head: string;
  base: string;
  labels?: string[];
}

export interface PRUpdateOptions {
  title?: string;
  body?: string;
}

/**
 * Creates a new pull request.
 */
export async function createPR(options: PROptions): Promise<string> {
  const token = core.getInput('token') || process.env.GITHUB_TOKEN;
  if (!token) {
    throw new Error('GITHUB_TOKEN is required');
  }

  const octokit = github.getOctokit(token);
  const { owner, repo } = github.context.repo;

  const pr = await octokit.rest.pulls.create({
    owner,
    repo,
    title: options.title,
    body: options.body,
    head: options.head,
    base: options.base,
  });

  // Add labels if specified
  if (options.labels && options.labels.length > 0) {
    await octokit.rest.issues.addLabels({
      owner,
      repo,
      issue_number: pr.data.number,
      labels: options.labels,
    });
  }

  return pr.data.html_url;
}

/**
 * Updates an existing pull request.
 */
export async function updatePR(
  prNumber: number,
  options: PRUpdateOptions
): Promise<void> {
  const token = core.getInput('token') || process.env.GITHUB_TOKEN;
  if (!token) {
    throw new Error('GITHUB_TOKEN is required');
  }

  const octokit = github.getOctokit(token);
  const { owner, repo } = github.context.repo;

  await octokit.rest.pulls.update({
    owner,
    repo,
    pull_number: prNumber,
    ...options,
  });
}

/**
 * Finds an existing PR by branch name or deduplication label.
 * Returns the PR number if found, undefined otherwise.
 */
export async function findExistingPR(
  branchName: string,
  dedupLabel?: string
): Promise<number | undefined> {
  const token = core.getInput('token') || process.env.GITHUB_TOKEN;
  if (!token) {
    throw new Error('GITHUB_TOKEN is required');
  }

  const octokit = github.getOctokit(token);
  const { owner, repo } = github.context.repo;

  // First try to find by branch name
  const prs = await octokit.rest.pulls.list({
    owner,
    repo,
    state: 'open',
    head: `${owner}:${branchName}`,
  });

  if (prs.data.length > 0) {
    return prs.data[0].number;
  }

  // If dedupLabel provided, try label-based filtering
  if (dedupLabel) {
    const labeledPRs = await octokit.rest.pulls.list({
      owner,
      repo,
      state: 'open',
    });

    for (const pr of labeledPRs.data) {
      if (pr.labels.some((label) => label.name === dedupLabel)) {
        return pr.number;
      }
    }
  }

  return undefined;
}

/**
 * Creates or updates a PR, using deduplication to avoid duplicate PRs.
 */
export async function createOrUpdatePR(
  options: PROptions,
  dedupContext?: Record<string, unknown>
): Promise<string> {
  const dedupLabel = dedupContext
    ? `trustify-da:${generateDeduplicationKey(dedupContext)}`
    : undefined;

  const existingPR = await findExistingPR(options.head, dedupLabel);

  if (existingPR) {
    await updatePR(existingPR, {
      title: options.title,
      body: options.body,
    });
    const { owner, repo } = github.context.repo;
    return `https://github.com/${owner}/${repo}/pull/${existingPR}`;
  }

  const labels = dedupLabel
    ? [...(options.labels || []), dedupLabel]
    : options.labels;

  return createPR({ ...options, labels });
}

/**
 * Creates a new branch from the current HEAD.
 */
export async function createBranch(branchName: string): Promise<void> {
  const token = core.getInput('token') || process.env.GITHUB_TOKEN;
  if (!token) {
    throw new Error('GITHUB_TOKEN is required');
  }

  const octokit = github.getOctokit(token);
  const { owner, repo } = github.context.repo;

  const ref = await octokit.rest.git.getRef({
    owner,
    repo,
    ref: `heads/${github.context.ref.replace('refs/heads/', '')}`,
  });

  await octokit.rest.git.createRef({
    owner,
    repo,
    ref: `refs/heads/${branchName}`,
    sha: ref.data.object.sha,
  });
}
