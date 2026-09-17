#!/usr/bin/env node

/**
 * Bundles the action into a single ESM file with esbuild.
 *
 * We emit ESM (not CommonJS) so the bundled JS client's `import.meta` usage
 * (`package_version.js`, the tree-sitter WASM parsers) is valid at runtime — under
 * ncc's CommonJS output those tokens were a parse-time SyntaxError and had to be
 * rewritten by a post-build patch. The action runs as `node20`, which loads this
 * file as ESM because package.json declares `"type": "module"`.
 */

import { copyFile, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { basename, dirname, join } from 'node:path';
import * as esbuild from 'esbuild';

// Start from a clean dist so stale output (e.g. old bundler chunks) can't linger.
await rm('dist', { recursive: true, force: true });

await esbuild.build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  platform: 'node',
  target: 'node20',
  format: 'esm',
  outfile: 'dist/index.js',
  sourcemap: true,
  // Prefer each dependency's ESM entry over its `main`. Some deps (e.g. jsonc-parser)
  // ship a UMD `main` whose runtime `require('./impl/...')` esbuild cannot bundle,
  // but a fully static ESM build under `module` — which bundles cleanly.
  mainFields: ['module', 'main'],
  // Aggregate bundled dependency licenses next to the output (dist/index.js.LEGAL.txt).
  legalComments: 'external',
  // Bundled CommonJS dependencies (@actions/*, yaml, ...) expect `require`,
  // `__dirname`, and `__filename` in scope. An ESM module has none of these, so
  // recreate them from import.meta.url; this also satisfies esbuild's dynamic
  // `require()` shim ("Dynamic require of X is not supported" otherwise).
  banner: {
    js: [
      "import { createRequire as __createRequire } from 'node:module';",
      "import { fileURLToPath as __fileURLToPath } from 'node:url';",
      "import { dirname as __pathDirname } from 'node:path';",
      'const require = __createRequire(import.meta.url);',
      'const __filename = __fileURLToPath(import.meta.url);',
      'const __dirname = __pathDirname(__filename);',
    ].join('\n'),
  },
});

console.log('✓ Built dist/index.js (ESM)');

// Copy the tree-sitter WASM assets next to the bundle. The client loads each via
// `new URL('<name>.wasm', import.meta.url)`, which resolves relative to dist/index.js;
// esbuild inlines the loader code but not these binary assets, so place them in dist/
// under the exact names the bundle requests.
const require = createRequire(import.meta.url);
const clientProviders = dirname(
  require.resolve('@trustify-da/trustify-da-javascript-client/dist/src/providers/gomod_parser.js')
);
// web-tree-sitter lives in the client's own node_modules (not necessarily hoisted),
// so resolve it relative to the client rather than this action.
const webTreeSitterDir = dirname(
  createRequire(join(clientProviders, 'gomod_parser.js')).resolve('web-tree-sitter')
);

const wasmAssets = [
  join(clientProviders, 'tree-sitter-containerfile.wasm'),
  join(clientProviders, 'tree-sitter-gomod.wasm'),
  join(clientProviders, 'tree-sitter-requirements.wasm'),
  join(webTreeSitterDir, 'web-tree-sitter.wasm'),
];
for (const src of wasmAssets) {
  await copyFile(src, join('dist', basename(src)));
}
console.log(`✓ Copied ${wasmAssets.length} WASM assets into dist/`);
