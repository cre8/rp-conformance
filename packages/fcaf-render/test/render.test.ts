import { readFile } from 'node:fs/promises';
import { definitions } from '@rp-conformance/definitions';
import { describe, expect, it } from 'vitest';
import { renderTestCase, testCasePath } from '../src/index';

const overlay = new URL('../../../fcaf-overlay/docs/fcaf/', import.meta.url);

// The executable definitions are the source of truth: each renders to the committed FCAF file, byte for byte.
describe('FCAF rendering', () => {
  it.each(definitions.map((d) => [d.id, d] as const))('%s renders to the committed FCAF test case', async (_id, definition) => {
    const committed = await readFile(new URL(testCasePath(definition.id), overlay), 'utf8');
    expect(renderTestCase(definition)).toBe(committed);
  });
});
