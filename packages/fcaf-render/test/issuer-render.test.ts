import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { issuerProfiles, variantOf, type IssuerTestCaseDefinition } from '@eudi-pcaf/core';
import { baselineDefinitions, definitions } from '@eudi-pcaf/definitions';
import { issuerDefinitions } from '@eudi-pcaf/issuer-definitions';
import { describe, expect, it } from 'vitest';
import { compareOverlay, groupByTestCase, ISSUER_TECHNOLOGY, issuerTestCasePath, renderBaseline, renderIssuer, renderIssuerTestCase } from '../src/index';

const overlay = fileURLToPath(new URL('../../../fcaf-overlay-issuer/docs/fcaf/', import.meta.url));
const groups = groupByTestCase(issuerDefinitions);

// The issuer definitions are the source of truth: the committed issuer overlay is exactly what they render to.
describe('FCAF rendering of the issuer test cases', () => {
  it('renders one page per test case ID, whatever the number of variants', () => {
    expect(groups.flat()).toHaveLength(issuerDefinitions.length);
    expect(new Set(issuerDefinitions.map((d) => d.id)).size).toBe(groups.length);
  });

  it.each(groups.map((g) => [g[0].id, g] as const))('%s renders to the committed FCAF test case', async (id, group) => {
    const committed = await readFile(`${overlay}${issuerTestCasePath(id)}`, 'utf8');
    expect(renderIssuerTestCase(group)).toBe(committed);
  });

  it('the whole issuer overlay, shared pages included, equals the committed fcaf-overlay-issuer/docs/fcaf byte for byte', async () => {
    const files = await renderIssuer(issuerDefinitions, await renderBaseline(definitions, baselineDefinitions));
    expect(await compareOverlay(files, overlay)).toEqual([]);
  });

  it('every profile condition and technology line is an item of the Provider ICS page', async () => {
    const icsPage = await readFile(`${overlay}ics-issuer.md`, 'utf8');
    for (const condition of Object.values(issuerProfiles)) expect(icsPage).toContain(`| ${condition.item} | ${condition.text} |`);
    for (const line of new Set(issuerDefinitions.flatMap((d) => d.technology))) {
      expect(ISSUER_TECHNOLOGY[line]).toBeDefined();
      expect(icsPage).toContain(`| N/A | ${line} | Yes/No |`);
    }
  });

  const step = (text: string, expect: string) => ({ text, expect: { codes: ['ISS' as const], text: expect } });
  const variant = (variants: IssuerTestCaseDefinition['variants'], format: string): IssuerTestCaseDefinition => ({
    id: 'PP_WS_IA_MainInteraction_901',
    objective: `Issue in ${format}.`,
    references: ['[OpenID4VCI] section 8'],
    profile: [issuerProfiles['P-PID'], issuerProfiles[format === 'mdoc' ? 'P-MD' : 'P-SD'], issuerProfiles['P-PA']],
    relevancy: 'EUDI_specific | EUDI_required',
    technology: ['OpenID4VCI', format === 'mdoc' ? 'ISO/IEC 18013-5 mdoc' : 'SD-JWT VC'],
    preconditions: [],
    variants,
    steps: [step(`Offer in ${format}.`, 'Issued.'), step('Same for all.', `Issued in ${format}.`)],
  });

  it('merges the variants of a test case: shared text once, differing text per variant, the variants in the comments', () => {
    const page = renderIssuerTestCase([variant(['SD', 'PA'], 'SD-JWT VC'), variant(['MD', 'PA'], 'mdoc')]);
    expect(page).toContain('## Objective\n\n- `SD+PA`: Issue in SD-JWT VC.\n- `MD+PA`: Issue in mdoc.\n');
    expect(page).toContain('## Technology\n\n- OpenID4VCI\n- SD-JWT VC\n- ISO/IEC 18013-5 mdoc\n');
    expect(page).toContain('## Test Scenario\n\n1. Per variant:\n    - `SD+PA`: Offer in SD-JWT VC.\n    - `MD+PA`: Offer in mdoc.\n2. Same for all.\n');
    expect(page).toContain('## Expected results\n\n1. Issued.\n2. Per variant:\n');
    expect(page).toContain('`SD+PA` (`P-PID`, `P-SD`, `P-PA`), `MD+PA` (`P-PID`, `P-MD`, `P-PA`).');
    expect(page.match(/^- Formats issued/gm)).toHaveLength(1);
  });

  it('refuses variants that differ where the page renders one text, or that are defined twice', () => {
    const other = { ...variant(['MD', 'PA'], 'mdoc'), preconditions: ['Other.'] };
    expect(() => renderIssuerTestCase([variant(['SD', 'PA'], 'SD-JWT VC'), other])).toThrow(/differ in preconditions/);
    expect(() => groupByTestCase([variant(['SD', 'PA'], 'x'), variant(['SD', 'PA'], 'y')])).toThrow(/SD\+PA is defined twice/);
    expect(variantOf(variant(['PA', 'SD'], 'x'))).toBe('SD+PA');
  });
});
