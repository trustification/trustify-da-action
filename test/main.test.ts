import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { run } from '../src/main.js';
import { runRemediateMode } from '../src/modes/remediate.js';
import { runCheckMode } from '../src/modes/check.js';
import { runSbomMode } from '../src/modes/sbom.js';

// @actions/core is deliberately NOT mocked: we drive the action through its real
// surface — inputs via INPUT_* env vars, results via the workflow commands it
// writes to stdout and the process exit code. The mode handlers ARE mocked,
// because main's job is to pick the right handler and surface failures, not to
// re-run each mode (that lives in the modes' own tests). loadConfig runs for
// real, so this also covers the main -> config wiring.
vi.mock('../src/modes/remediate.js', () => ({ runRemediateMode: vi.fn() }));
vi.mock('../src/modes/check.js', () => ({ runCheckMode: vi.fn() }));
vi.mock('../src/modes/sbom.js', () => ({ runSbomMode: vi.fn() }));

const HANDLERS = {
  remediate: vi.mocked(runRemediateMode),
  check: vi.mocked(runCheckMode),
  sbom: vi.mocked(runSbomMode),
};
type Mode = keyof typeof HANDLERS;

// core.getInput('foo') reads process.env.INPUT_FOO.
function setInput(name: string, value: string) {
  process.env[`INPUT_${name.toUpperCase()}`] = value;
}

// Collects everything the action writes to stdout, which is where @actions/core
// emits its `::error::`, `::warning::`, etc. workflow commands.
let stdout: string;
let stdoutSpy: { mockRestore(): void };

beforeEach(() => {
  vi.clearAllMocks();
  for (const key of Object.keys(process.env)) {
    if (key.startsWith('INPUT_')) delete process.env[key];
  }
  process.exitCode = undefined; // setFailed sets this to 1; start clean
  stdout = '';
  stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: unknown) => {
    stdout += String(chunk);
    return true;
  }) as typeof process.stdout.write);
});

afterEach(() => {
  stdoutSpy.mockRestore();
  process.exitCode = undefined; // don't let a tested failure fail the vitest run
});

describe('main dispatch', () => {
  // Adding a mode is a new key in HANDLERS plus a switch arm in main.ts.
  for (const mode of Object.keys(HANDLERS) as Mode[]) {
    it(`routes "${mode}" to its handler and succeeds`, async () => {
      setInput('mode', mode);

      await run();

      expect(HANDLERS[mode]).toHaveBeenCalledOnce();
      for (const [name, fn] of Object.entries(HANDLERS)) {
        if (name !== mode) expect(fn).not.toHaveBeenCalled();
      }
      expect(process.exitCode).toBeFalsy();
      expect(stdout).not.toContain('::error::');
    });
  }

  it('matches the mode case-insensitively', async () => {
    setInput('mode', 'ReMeDiAtE');

    await run();

    expect(HANDLERS.remediate).toHaveBeenCalledOnce();
  });

  it('fails with a readable message for an unknown mode', async () => {
    setInput('mode', 'bogus');

    await run();

    expect(process.exitCode).toBe(1);
    expect(stdout).toContain('::error::');
    expect(stdout).toContain('Invalid mode: bogus');
    for (const fn of Object.values(HANDLERS)) expect(fn).not.toHaveBeenCalled();
  });

  it('surfaces a handler error via setFailed instead of rejecting', async () => {
    setInput('mode', 'check');
    HANDLERS.check.mockRejectedValueOnce(new Error('backend unreachable'));

    await expect(run()).resolves.toBeUndefined(); // run() swallows and reports
    expect(process.exitCode).toBe(1);
    expect(stdout).toContain('backend unreachable');
  });
});
