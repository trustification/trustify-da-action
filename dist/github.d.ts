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
export declare function createPR(options: PROptions): Promise<string>;
/**
 * Updates an existing pull request.
 */
export declare function updatePR(prNumber: number, options: PRUpdateOptions): Promise<void>;
/**
 * Finds an existing PR by branch name or deduplication label.
 * Returns the PR number if found, undefined otherwise.
 */
export declare function findExistingPR(branchName: string, dedupLabel?: string): Promise<number | undefined>;
/**
 * Creates or updates a PR, using deduplication to avoid duplicate PRs.
 */
export declare function createOrUpdatePR(options: PROptions, dedupContext?: Record<string, unknown>): Promise<string>;
/**
 * Creates a new branch from the current HEAD.
 */
export declare function createBranch(branchName: string): Promise<void>;
