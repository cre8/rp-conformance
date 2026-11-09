// Renders the FCAF overlay (fcaf-overlay/docs/fcaf): the test cases from the definitions, the overviews, area and layer
// pages and baseline lists of the Relying Party SUT, the Relying Party ICS, and modified copies of four FCAF pages.
import { readFile } from 'node:fs/promises';
import { parseTestCaseId, type TestCaseDefinition } from '@rp-conformance/core';
import { AREA_TITLE, CLASS_DIR, CLASS_TITLE, LAYER_DIR, LAYER_TITLE, renderTestCase, testCasePath, testCasePathInSut } from './testcase';

/** The FCAF pages the overlay modifies, from the `submitted` branch (see upstream/README.md). */
export interface UpstreamPages {
  defaults: string;
  references: string;
  nav: string;
  sutsIndex: string;
}

/** The shared pages of the Relying Party SUT (pages/). */
export interface SharedPages {
  defaultsRp: string;
  icsRp: string;
  referencesRp: string;
  relyingParty: string;
  rpWs: string;
  rpPp: string;
  navRp: string;
}

const PACKAGE = new URL('../', import.meta.url);

const read = (path: string) => readFile(new URL(path, PACKAGE), 'utf8');

export async function loadUpstreamPages(): Promise<UpstreamPages> {
  return {
    defaults: await read('upstream/defaults.md'),
    references: await read('upstream/references.md'),
    nav: await read('upstream/.nav.yml'),
    sutsIndex: await read('upstream/suts/index.md'),
  };
}

export async function loadSharedPages(): Promise<SharedPages> {
  return {
    defaultsRp: await read('pages/defaults-rp.md'),
    icsRp: await read('pages/ics-rp.md'),
    referencesRp: await read('pages/references-rp.md'),
    relyingParty: await read('pages/relying-party.md'),
    rpWs: await read('pages/rp-ws.md'),
    rpPp: await read('pages/rp-pp.md'),
    navRp: await read('pages/nav-rp.yml'),
  };
}

const trimNewlines = (text: string) => text.replace(/\n+$/, '');
/** Every file ends with exactly one newline. */
const normalise = (text: string) => `${trimNewlines(text)}\n`;

const testCasesPage = (title: string) => `# ${title} test cases\n\n{% include-markdown "./*/index.md" heading-offset=1 comments=true %}\n`;
const layerPage = (title: string) => `# ${title}\n\n{% include-markdown "./*/index.md" heading-offset=1 comments=true %}\n`;
const areaPage = (layer: string, area: string) =>
  `# ${layer} - ${area}\n\n{% include-markdown "./[A-Z]*.md" heading-offset=2 comments=true %}\n`;

function insertAfter(text: string, anchor: string, insertion: string, where: 'before' | 'after'): string {
  const at = text.indexOf(anchor);
  if (at < 0) throw new Error(`anchor not found: ${JSON.stringify(anchor)}`);
  return where === 'before' ? text.slice(0, at) + insertion + text.slice(at) : text.slice(0, at + anchor.length) + insertion + text.slice(at + anchor.length);
}

/**
 * Renders the overlay as a map from path below `docs/fcaf` to file content. Test cases appear in the baseline lists in
 * the order of `definitions`.
 */
export function renderOverlay(definitions: TestCaseDefinition[], upstream: UpstreamPages, pages: SharedPages): Map<string, string> {
  const files = new Map<string, string>();
  const write = (path: string, text: string) => {
    if (files.has(path)) throw new Error(`${path} is rendered twice`);
    files.set(path, normalise(text));
  };
  const ids = definitions.map((d) => d.id);
  const duplicates = ids.filter((id, i) => ids.indexOf(id) !== i);
  if (duplicates.length) throw new Error(`duplicate test case IDs: ${duplicates.join(', ')}`);

  for (const definition of definitions) write(testCasePath(definition.id), renderTestCase(definition));

  const rp = 'suts/relying_party';
  write(`${rp}/index.md`, pages.relyingParty);
  write(`${rp}/wallet_solution/rp_ws.md`, pages.rpWs);
  write(`${rp}/pid_provider/rp_pp.md`, pages.rpPp);
  for (const [sutClass, classDir] of Object.entries(CLASS_DIR)) {
    const mine = definitions.filter((d) => parseTestCaseId(d.id).sutClass === sutClass);
    write(`${rp}/${classDir}/test-cases.md`, testCasesPage(CLASS_TITLE[sutClass]));
    const list = mine.map((d) => `- [${d.id}](${testCasePathInSut(d.id).slice(classDir.length + 1)})`).join('\n');
    write(
      `${rp}/${classDir}/baseline-tests.md`,
      [`# ${CLASS_TITLE[sutClass]} baseline tests`, `The following ${mine.length} test cases form the baseline test set.`, list].join('\n\n'),
    );
    const layers = [...new Set(mine.map((d) => parseTestCaseId(d.id).layer))].sort();
    for (const layer of layers) {
      write(`${rp}/${classDir}/${LAYER_DIR[layer]}/index.md`, layerPage(LAYER_TITLE[layer]));
      const areas = [...new Set(mine.filter((d) => parseTestCaseId(d.id).layer === layer).map((d) => parseTestCaseId(d.id).area))].sort();
      for (const area of areas) {
        if (!AREA_TITLE[area]) throw new Error(`no title for area ${area}`);
        write(`${rp}/${classDir}/${LAYER_DIR[layer]}/${area}/index.md`, areaPage(LAYER_TITLE[layer], AREA_TITLE[area]));
      }
    }
  }

  write('ics-rp.md', pages.icsRp);
  write('defaults.md', `${trimNewlines(upstream.defaults)}\n\n${pages.defaultsRp}`);
  write('references.md', `${trimNewlines(upstream.references)}\n${pages.referencesRp}`);
  const sharedAnchor = '      - Shared: suts/shared/index.md\n';
  const icsAnchor = '  - ICS: ics.md\n';
  let nav = insertAfter(upstream.nav, sharedAnchor, pages.navRp, 'before');
  nav = insertAfter(nav, icsAnchor, '  - ICS (Relying Party): ics-rp.md\n', 'after');
  write('.nav.yml', nav);
  const scope = 'For the initial phase of the FCAF, the only SUT in scope is: **Wallet Solution**\n';
  write(
    'suts/index.md',
    insertAfter(upstream.sutsIndex, scope, '\nA draft **Relying Party** SUT is defined in addition: see [Relying Party (SUT)](relying_party/index.md).\n', 'after'),
  );
  return files;
}
