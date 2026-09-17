import { defineConfig } from 'vitest/config';

// E2E run: only the e2e suite, with a longer timeout for Maven resolution and
// the backend round-trip.
export default defineConfig({
  test: {
    include: ['test/e2e/**/*.test.ts'],
    testTimeout: 120_000,
  },
});
