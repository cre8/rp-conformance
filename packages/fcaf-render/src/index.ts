// Renders FCAF test case markdown from the executable definitions. Phase 0 holds the per-test-case part, a port of
// render() in generator/render.py; Phase 1 ports the shared pages (generator/pages.py) and writes the overlay.
import { parseTestCaseId, type TestCaseDefinition } from '@rp-conformance/core';

const CLASS_DIR = { WS: 'wallet_solution', PP: 'pid_provider' } as Record<string, string>;
const LAYER_DIR = { IA: 'Interaction', SM: 'SecurityMechanisms' } as Record<string, string>;

const numbered = (items: string[]) => items.map((text, i) => `${i + 1}. ${text}`).join('\n');
const bullets = (items: string[]) => items.map((text) => `- ${text}`).join('\n');

/** The FCAF markdown of one test case, as generator/render.py writes it. */
export function renderTestCase(definition: TestCaseDefinition): string {
  const parts = [`# ${definition.id}`, '## Objective', definition.objective, '## References', bullets(definition.references)];
  parts.push('## Profile applicability', definition.profile.length ? bullets(definition.profile.map((p) => p.text)) : 'None');
  parts.push('## EUDI-wallet relevancy', definition.relevancy);
  if (definition.technology.length) parts.push('## Technology', bullets(definition.technology));
  parts.push('## Preconditions', definition.preconditions.length ? numbered(definition.preconditions) : 'None');
  parts.push('## Test Scenario', numbered(definition.steps.map((s) => s.text)));
  parts.push('## Expected results', numbered(definition.steps.map((s) => s.expect.text)));
  if (definition.comments?.length) parts.push('## Comments', definition.comments.join('\n\n'));
  return `${parts.join('\n\n')}\n`;
}

/** Path of a test case below the overlay root `docs/fcaf`. */
export function testCasePath(id: string): string {
  const { sutClass, layer, area } = parseTestCaseId(id);
  const classDir = CLASS_DIR[sutClass];
  const layerDir = LAYER_DIR[layer];
  if (!classDir || !layerDir) throw new Error(`${id}: no directory for class ${sutClass} or layer ${layer}`);
  return `suts/relying_party/${classDir}/${layerDir}/${area}/${id}.md`;
}
