import { mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join, relative } from 'node:path';
import type { TestCaseDefinition } from '@rp-conformance/core';
import { loadSharedPages, loadUpstreamPages, renderOverlay } from './overlay';

/** Renders the overlay of the given definitions with the vendored FCAF base pages and the shared pages. */
export async function renderBaseline(definitions: TestCaseDefinition[]): Promise<Map<string, string>> {
  return renderOverlay(definitions, await loadUpstreamPages(), await loadSharedPages());
}

async function listFiles(root: string): Promise<string[]> {
  const entries = await readdir(root, { recursive: true, withFileTypes: true }).catch(() => []);
  return entries.filter((e) => e.isFile()).map((e) => relative(root, join(e.parentPath, e.name)).split('\\').join('/'));
}

export interface OverlayDifference {
  path: string;
  problem: 'missing' | 'differs' | 'not rendered';
}

/** Compares the rendered files with a directory: every rendered file exists with the same bytes, and nothing else. */
export async function compareOverlay(files: Map<string, string>, root: string): Promise<OverlayDifference[]> {
  const differences: OverlayDifference[] = [];
  for (const [path, content] of files) {
    const existing = await readFile(join(root, path), 'utf8').catch(() => undefined);
    if (existing === undefined) differences.push({ path, problem: 'missing' });
    else if (existing !== content) differences.push({ path, problem: 'differs' });
  }
  for (const path of await listFiles(root)) if (!files.has(path)) differences.push({ path, problem: 'not rendered' });
  return differences.sort((a, b) => a.path.localeCompare(b.path));
}

/** Replaces a directory with the rendered files. */
export async function writeOverlay(files: Map<string, string>, root: string): Promise<void> {
  await rm(root, { recursive: true, force: true });
  for (const [path, content] of files) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), content);
  }
}
