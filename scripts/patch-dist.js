#!/usr/bin/env node

/**
 * Post-build script to patch dist/index.js
 * Replaces ESM-only features (import.meta) with CommonJS equivalents
 */

const fs = require('fs');
const path = require('path');

const distPath = path.join(__dirname, '..', 'dist', 'index.js');

console.log('Patching dist/index.js for CommonJS compatibility...');

let content = fs.readFileSync(distPath, 'utf-8');

// Replace import.meta.dirname with __dirname
const beforeDirname = content.match(/import\.meta\.dirname/g)?.length || 0;
content = content.replace(/import\.meta\.dirname/g, '__dirname');

// Replace import.meta.url with file URL using __filename
const beforeUrl = content.match(/import\.meta\.url/g)?.length || 0;
content = content.replace(/import\.meta\.url/g, '`file://${__filename}`');

fs.writeFileSync(distPath, content, 'utf-8');

console.log(`Patched ${beforeDirname} import.meta.dirname references`);
console.log(`Patched ${beforeUrl} import.meta.url references`);
console.log('✓ Patch complete');
