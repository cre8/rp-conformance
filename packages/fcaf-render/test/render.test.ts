import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { ics } from '@rp-conformance/core';
import { baselineDefinitions, definitions, attestationProviderDefinitions } from '@rp-conformance/definitions';
import { describe, expect, it } from 'vitest';
import { compareOverlay, renderBaseline, renderTestCase, testCasePath } from '../src/index';

const overlay = fileURLToPath(new URL('../../../fcaf-overlay/docs/fcaf/', import.meta.url));

// The executable definitions are the source of truth: the committed overlay is exactly what they render to.
describe('FCAF rendering', () => {
  it('there are 121 baseline test cases, 185 further ones, and the 150 of RP_AP', () => {
    expect(baselineDefinitions).toHaveLength(121);
    expect(definitions).toHaveLength(470);
    expect(definitions.slice(0, 121)).toEqual(baselineDefinitions);
  });

  it('RP_AP holds the Q, PB and E variants of every RP_PP test case except _011, with the same number and format', () => {
    const pp = definitions.filter((d) => d.id.startsWith('RP_PP_') && !/_011[ab]_UF$/.test(d.id));
    const expected = pp.flatMap((d) => ['Q', 'PB', 'E'].map((c) => d.id.replace(/^RP_PP_(.*_\d{3}[a-z]?)(_UF)?$/, `RP_AP_$1${c}$2`)));
    expect(attestationProviderDefinitions.map((d) => d.id)).toEqual(expected);
    expect(definitions.slice(-150)).toEqual(attestationProviderDefinitions);
  });

  it.each(definitions.map((d) => [d.id, d] as const))('%s renders to the committed FCAF test case', async (_id, definition) => {
    const committed = await readFile(`${overlay}${testCasePath(definition.id)}`, 'utf8');
    expect(renderTestCase(definition)).toBe(committed);
  });

  it('the whole overlay, shared pages included, equals the committed fcaf-overlay/docs/fcaf byte for byte', async () => {
    const files = await renderBaseline(definitions, baselineDefinitions);
    expect(await compareOverlay(files, overlay)).toEqual([]);
  });

  it('every ICS condition a definition can use is worded as in the Relying Party ICS', async () => {
    const icsPage = await readFile(`${overlay}ics-rp.md`, 'utf8');
    for (const condition of Object.values(ics)) expect(icsPage).toContain(`| ${condition.item} | ${condition.text} |`);
  });
});
