import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { ics } from '@rp-conformance/core';
import { definitions } from '@rp-conformance/definitions';
import { describe, expect, it } from 'vitest';
import { compareOverlay, renderBaseline, renderTestCase, testCasePath } from '../src/index';

const overlay = fileURLToPath(new URL('../../../fcaf-overlay/docs/fcaf/', import.meta.url));

// The executable definitions are the source of truth: the committed overlay is exactly what they render to.
describe('FCAF rendering', () => {
  it('there are 121 baseline test cases', () => {
    expect(definitions).toHaveLength(121);
  });

  it.each(definitions.map((d) => [d.id, d] as const))('%s renders to the committed FCAF test case', async (_id, definition) => {
    const committed = await readFile(`${overlay}${testCasePath(definition.id)}`, 'utf8');
    expect(renderTestCase(definition)).toBe(committed);
  });

  it('the whole overlay, shared pages included, equals the committed fcaf-overlay/docs/fcaf byte for byte', async () => {
    const files = await renderBaseline(definitions);
    expect(await compareOverlay(files, overlay)).toEqual([]);
  });

  it('every ICS condition a definition can use is worded as in the Relying Party ICS', async () => {
    const icsPage = await readFile(`${overlay}ics-rp.md`, 'utf8');
    for (const condition of Object.values(ics)) expect(icsPage).toContain(`| ${condition.item} | ${condition.text} |`);
  });
});
