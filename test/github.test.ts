import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as core from '@actions/core';
import * as github from '@actions/github';
import {
  createPR,
  updatePR,
  findExistingPR,
  createOrUpdatePR,
  createBranch,
} from '../src/github.js';

vi.mock('@actions/core');
vi.mock('@actions/github');

// A fake Octokit exposing just the REST calls github.ts uses. Each test tweaks
// return values via the returned handle.
function fakeOctokit() {
  const octokit = {
    rest: {
      pulls: {
        create: vi.fn().mockResolvedValue({ data: { number: 42, html_url: 'https://gh/pr/42' } }),
        update: vi.fn().mockResolvedValue({}),
        list: vi.fn().mockResolvedValue({ data: [] }),
      },
      issues: {
        addLabels: vi.fn().mockResolvedValue({}),
      },
      git: {
        getRef: vi.fn().mockResolvedValue({ data: { object: { sha: 'base-sha' } } }),
        createRef: vi.fn().mockResolvedValue({}),
      },
    },
  };
  vi.mocked(github.getOctokit).mockReturnValue(octokit as unknown as ReturnType<typeof github.getOctokit>);
  return octokit;
}

const PR = { title: 'Fix', body: 'body', head: 'fix-branch', base: 'main' };

describe('github', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // The functions read a token from the `token` input; provide one by default.
    vi.mocked(core.getInput).mockReturnValue('test-token');
    // github.context.repo / .ref are read-only getters; stub them.
    Object.defineProperty(github, 'context', {
      value: { repo: { owner: 'acme', repo: 'app' }, ref: 'refs/heads/main' },
      configurable: true,
    });
  });

  describe('createPR', () => {
    it('creates the PR and returns its url', async () => {
      const octokit = fakeOctokit();

      const url = await createPR(PR);

      expect(url).toBe('https://gh/pr/42');
      expect(octokit.rest.pulls.create).toHaveBeenCalledWith(
        expect.objectContaining({ owner: 'acme', repo: 'app', head: 'fix-branch', base: 'main' })
      );
      expect(octokit.rest.issues.addLabels).not.toHaveBeenCalled();
    });

    it('adds labels when provided', async () => {
      const octokit = fakeOctokit();

      await createPR({ ...PR, labels: ['security'] });

      expect(octokit.rest.issues.addLabels).toHaveBeenCalledWith(
        expect.objectContaining({ issue_number: 42, labels: ['security'] })
      );
    });

    it('throws when no token is available', async () => {
      fakeOctokit();
      vi.mocked(core.getInput).mockReturnValue('');
      delete process.env.GITHUB_TOKEN;

      await expect(createPR(PR)).rejects.toThrow('GITHUB_TOKEN is required');
    });
  });

  describe('updatePR', () => {
    it('updates the given PR number', async () => {
      const octokit = fakeOctokit();

      await updatePR(7, { title: 'new' });

      expect(octokit.rest.pulls.update).toHaveBeenCalledWith(
        expect.objectContaining({ pull_number: 7, title: 'new' })
      );
    });
  });

  describe('findExistingPR', () => {
    it('returns the PR number found by branch name', async () => {
      const octokit = fakeOctokit();
      octokit.rest.pulls.list.mockResolvedValueOnce({ data: [{ number: 5 }] });

      expect(await findExistingPR('fix-branch')).toBe(5);
      expect(octokit.rest.pulls.list).toHaveBeenCalledWith(
        expect.objectContaining({ head: 'acme:fix-branch', state: 'open' })
      );
    });

    it('falls back to the dedup label when no branch match exists', async () => {
      const octokit = fakeOctokit();
      octokit.rest.pulls.list
        .mockResolvedValueOnce({ data: [] }) // branch lookup: none
        .mockResolvedValueOnce({ data: [{ number: 9, labels: [{ name: 'dedup-1' }] }] });

      expect(await findExistingPR('fix-branch', 'dedup-1')).toBe(9);
    });

    it('returns undefined when nothing matches', async () => {
      fakeOctokit(); // list defaults to empty
      expect(await findExistingPR('fix-branch', 'dedup-1')).toBeUndefined();
    });
  });

  describe('createOrUpdatePR', () => {
    it('updates in place when a matching PR already exists', async () => {
      const octokit = fakeOctokit();
      octokit.rest.pulls.list.mockResolvedValueOnce({ data: [{ number: 3 }] });

      const url = await createOrUpdatePR(PR);

      expect(octokit.rest.pulls.update).toHaveBeenCalledWith(
        expect.objectContaining({ pull_number: 3 })
      );
      expect(octokit.rest.pulls.create).not.toHaveBeenCalled();
      expect(url).toBe('https://github.com/acme/app/pull/3');
    });

    it('creates a new PR and appends a dedup label from the context', async () => {
      const octokit = fakeOctokit();

      await createOrUpdatePR(PR, { cve: 'CVE-2024-1' });

      const labels = octokit.rest.issues.addLabels.mock.calls[0][0].labels as string[];
      expect(labels.some((l) => l.startsWith('trustify-da:'))).toBe(true);
    });
  });

  describe('createBranch', () => {
    it('creates a ref pointing at the current HEAD sha', async () => {
      const octokit = fakeOctokit();

      await createBranch('new-branch');

      expect(octokit.rest.git.getRef).toHaveBeenCalledWith(
        expect.objectContaining({ ref: 'heads/main' })
      );
      expect(octokit.rest.git.createRef).toHaveBeenCalledWith(
        expect.objectContaining({ ref: 'refs/heads/new-branch', sha: 'base-sha' })
      );
    });
  });
});
