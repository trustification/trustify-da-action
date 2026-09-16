import { defineConfig, configDefaults } from 'vitest/config';

// Default unit-test run: everything under test/ except the e2e suite, which
// needs a live backend and is run separately via vitest.e2e.config.ts.
export default defineConfig({
  test: {
    exclude: [...configDefaults.exclude, 'test/e2e/**'],
  },
});
