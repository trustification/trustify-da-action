import * as core from '@actions/core';
import { mkdir, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { findManifests } from '@trustify-da/trustify-da-javascript-client/dist/src/remediate.js';
import daClient from '@trustify-da/trustify-da-javascript-client/dist/src/index.js';
import type { ActionConfig } from '../config.js';

interface SbomEntry {
  manifest: string;
  fileName: string;
  filePath: string;
  componentName: string;
  dependencyCount: number;
}

export async function runSbomMode(_config: ActionConfig): Promise<void> {
  core.info('Running in sbom mode');

  const workspacePath = process.env.GITHUB_WORKSPACE || process.cwd();

  const manifests = findManifests(workspacePath);
  core.info(
    manifests.length === 0
      ? 'No supported manifests found.'
      : `Generating SBOMs for ${manifests.length} manifest(s)...`
  );

  if (manifests.length === 0) {
    core.setOutput('sbom-path', '');
    writeSummary([]);
    return;
  }

  const outputDir = join(
    process.env.RUNNER_TEMP || workspacePath,
    'trustify-da-sboms'
  );
  await mkdir(outputDir, { recursive: true });

  const entries: SbomEntry[] = [];
  const usedFileNames = new Set<string>();

  for (const manifest of manifests) {
    const relPath = relative(workspacePath, manifest) || manifest;
    core.info(`Generating SBOM for ${relPath}`);

    let sbom: Record<string, unknown>;
    try {
      sbom = await daClient.generateSbom(manifest, {}) as Record<string, unknown>;
    } catch (error) {
      throw new Error(
        `SBOM generation failed for ${relPath}: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    const fileName = flattenPath(relPath, usedFileNames);
    const filePath = join(outputDir, fileName);
    await writeFile(filePath, JSON.stringify(sbom, null, 2));

    const metadata = (sbom.metadata as Record<string, unknown>) ?? {};
    const component = (metadata.component as Record<string, unknown>) ?? {};
    const components = (sbom.components as unknown[]) ?? [];

    entries.push({
      manifest: relPath,
      fileName,
      filePath,
      componentName: String(component.name ?? 'unknown'),
      dependencyCount: components.length,
    });

    core.info(`Wrote ${fileName} (${components.length} components)`);
  }

  core.setOutput('sbom-path', outputDir);
  writeSummary(entries);
}

function flattenPath(relPath: string, used: Set<string>): string {
  let base = relPath.replace(/[\\/]/g, '-') + '.cdx.json';
  if (!used.has(base)) {
    used.add(base);
    return base;
  }
  let i = 2;
  while (used.has(base)) {
    base = relPath.replace(/[\\/]/g, '-') + `.${i}.cdx.json`;
    i++;
  }
  used.add(base);
  return base;
}

function writeSummary(entries: SbomEntry[]): void {
  const sections: string[] = [];

  sections.push('# Trustify Dependency Analytics — SBOM Report');

  if (entries.length === 0) {
    sections.push('No SBOMs generated.');
  } else {
    sections.push(
      [
        '## Generated SBOMs',
        '',
        '| Manifest | Component | Dependencies | File |',
        '| --- | --- | --- | --- |',
        ...entries.map(
          (e) =>
            `| ${e.manifest} | ${e.componentName} | ${e.dependencyCount} | ${e.fileName} |`
        ),
      ].join('\n')
    );
  }

  const markdown = sections.join('\n\n') + '\n';
  void core.summary.addRaw(markdown).write();
}
