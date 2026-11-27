// Renders the issuer overlay (fcaf-overlay-issuer/docs/fcaf, issuer harness design decision 1): the PID Provider SUT
// with its test cases, class, layer and area pages, the Provider ICS, and the FCAF pages the RP overlay modifies, with
// the PID Provider's additions. It is laid over the FCAF `submitted` content with the RP overlay, so its copies of
// defaults.md, references.md, .nav.yml and suts/index.md are the RP overlay's plus the issuer additions.
import { readFile } from 'node:fs/promises';
import { ISSUER_ICS_ITEMS, parseIssuerTestCaseId, type IssuerTestCaseDefinition } from '@eudi-pcaf/core';
import {
  groupByTestCase,
  ISSUER_CLASS_DIR,
  ISSUER_CLASS_NAV,
  ISSUER_CLASS_TITLE,
  ISSUER_LAYER_DIR,
  ISSUER_LAYER_TITLE,
  issuerAreaTitle,
  issuerTestCasePath,
  ISSUER_SUTS,
  renderIssuerTestCase,
  sutDirOf,
} from './issuer';

/** The hand-written pages of the PID Provider SUT (pages/). */
export interface IssuerPages {
  pidProvider: string;
  /** Issue 27: the overview of the Attestation Provider SUT. */
  attestationProvider: string;
  classOverview: Record<string, string>;
  defaults: string;
  ics: string;
  references: string;
}

const PACKAGE = new URL('../', import.meta.url);
const read = (path: string) => readFile(new URL(path, PACKAGE), 'utf8');

export async function loadIssuerPages(): Promise<IssuerPages> {
  const classOverview: Record<string, string> = {};
  for (const [sutClass, { overview }] of Object.entries(ISSUER_CLASS_NAV)) classOverview[sutClass] = await read(`pages/${overview}`);
  return {
    pidProvider: await read('pages/pid-provider.md'),
    attestationProvider: await read('pages/attestation-provider.md'),
    classOverview,
    defaults: await read('pages/defaults-issuer.md'),
    ics: await read('pages/ics-issuer.md'),
    references: await read('pages/references-issuer.md'),
  };
}

/**
 * The surrogate ICS items behind the `Technology` lines of the issuer definitions, as `ics-rp.md` has them for the RP
 * test cases: the FCAF lint looks every line up in the ICS. A definition with a line not listed here fails rendering.
 */
export const ISSUER_TECHNOLOGY: Record<string, string> = {
  OpenID4VCI: 'Every Provider; [OpenID4VCI].',
  HAIP: 'Every Provider; [HAIP] section 4.',
  'SD-JWT VC': 'Follows ICS-02 (`P-SD`); [SD-JWT VC].',
  'ISO/IEC 18013-5 mdoc': 'Follows ICS-02 (`P-MD`); [ISO/IEC 18013-5].',
  'Attestation-Based Client Authentication': 'Every Provider; Wallet Instance Attestation as client authentication, [IETF draft-attestation-based-client-auth].',
  'Token Status List': 'Follows ICS-05 (`P-REV`); [Token Status List].',
  HTTP: 'Every Provider that publishes status lists or identifier lists.',
  // Issue 26: PP_Inf_SM_TrustMechanisms
  'ETSI TS 119 602 LoTE': 'Every Provider; the Wallet Provider list `TL-WP`, [ETSI TS 119 602].',
};

const trimNewlines = (text: string) => text.replace(/\n+$/, '');
const normalise = (text: string) => `${trimNewlines(text)}\n`;
const code = (text: string) => `\`${text}\``;

const layerPage = (title: string) => `# ${title}\n\n{% include-markdown "./*/index.md" heading-offset=1 comments=true %}\n`;
const areaPage = (layer: string, area: string) =>
  `# ${layer} - ${area}\n\n{% include-markdown "./[A-Z]*.md" heading-offset=2 comments=true %}\n`;

function insertAt(text: string, anchor: string, insertion: string, where: 'before' | 'after'): string {
  const at = text.indexOf(anchor);
  if (at < 0) throw new Error(`anchor not found: ${JSON.stringify(anchor)}`);
  return where === 'before' ? text.slice(0, at) + insertion + text.slice(at) : text.slice(0, at + anchor.length) + insertion + text.slice(at + anchor.length);
}

/** The Provider ICS page: the hand-written introduction, the items ICS-01 to ICS-19 and the surrogate technology items. */
export function renderIssuerIcs(intro: string, technology: string[]): string {
  const items = Object.entries(ISSUER_ICS_ITEMS).map(([id, item]) => {
    const profiles = item.profiles.map(code).join(', ');
    const policy = 'policy' in item && item.policy ? 'Decides the `POLICY` expected results.' : '';
    return `| ${id} | ${item.question} | ${profiles || 'Declared values'} | ${policy} |`;
  });
  const surrogate = technology.map((line) => `| N/A | ${line} | Yes/No | ${ISSUER_TECHNOLOGY[line]} |`);
  return [
    trimNewlines(intro),
    '## Provider',
    '| ID | ICS item | Profiles | EUDI specifics |\n| --- | --- | --- | --- |\n' + items.join('\n'),
    '## Technology',
    'Surrogate items that select test cases through their Technology section.',
    '| ID | ICS item | Options | EUDI specifics |\n| --- | --- | --- | --- |\n' + surrogate.join('\n'),
  ].join('\n\n');
}

/** The navigation of the PID Provider and Attestation Provider SUTs, below `Test Suites by SUTs`. */
function issuerNav(): string {
  const lines: string[] = [];
  for (const sut of ISSUER_SUTS) {
    lines.push(`      - ${sut.title}:`, `          - Overview: ${sut.dir}/index.md`, '          - Test Classes:');
    for (const [sutClass, { label, overview }] of Object.entries(ISSUER_CLASS_NAV).filter(([c]) => c.startsWith(`${sut.prefix}_`))) {
      const dir = `${sut.dir}/${ISSUER_CLASS_DIR[sutClass]}`;
      lines.push(`              - ${label}:`, `                  - Overview: ${dir}/${overview}`, `                  - Test cases: ${dir}/test-cases.md`);
    }
  }
  return `${lines.join('\n')}\n`;
}

/**
 * Renders the issuer overlay as a map from path below `docs/fcaf` to file content: one page per test case ID (its
 * variants merged), and the RP overlay's copies of the modified FCAF pages (`rp`, from `renderOverlay`) with the
 * PID Provider's additions.
 */
export function renderIssuerOverlay(definitions: IssuerTestCaseDefinition[], rp: Map<string, string>, pages: IssuerPages): Map<string, string> {
  const files = new Map<string, string>();
  const write = (path: string, text: string) => {
    if (files.has(path)) throw new Error(`${path} is rendered twice`);
    files.set(path, normalise(text));
  };
  const fromRp = (path: string) => {
    const text = rp.get(path);
    if (text === undefined) throw new Error(`the RP overlay has no ${path}`);
    return text;
  };

  const groups = groupByTestCase(definitions);
  for (const group of groups) write(issuerTestCasePath(group[0].id), renderIssuerTestCase(group));

  const ids = groups.map((g) => g[0].id);
  const unknownClass = ids.filter((id) => !ISSUER_CLASS_DIR[parseIssuerTestCaseId(id).sutClass]);
  if (unknownClass.length) throw new Error(`no SUT directory for ${unknownClass.join(', ')}`);

  for (const sut of ISSUER_SUTS) write(`${sut.dir}/index.md`, sut.prefix === 'PP' ? pages.pidProvider : pages.attestationProvider);
  for (const [sutClass, classDir] of Object.entries(ISSUER_CLASS_DIR)) {
    const dir = `${sutDirOf(sutClass)}/${classDir}`;
    write(`${dir}/${ISSUER_CLASS_NAV[sutClass].overview}`, pages.classOverview[sutClass]);
    const mine = ids.filter((id) => parseIssuerTestCaseId(id).sutClass === sutClass).map(parseIssuerTestCaseId);
    write(
      `${dir}/test-cases.md`,
      mine.length
        ? `# ${ISSUER_CLASS_TITLE[sutClass]} test cases\n\n{% include-markdown "./*/index.md" heading-offset=1 comments=true %}\n`
        : `# ${ISSUER_CLASS_TITLE[sutClass]} test cases\n\nNo test cases of this class are written yet.\n`,
    );
    for (const layer of [...new Set(mine.map((p) => p.layer))].sort()) {
      write(`${dir}/${ISSUER_LAYER_DIR[layer]}/index.md`, layerPage(ISSUER_LAYER_TITLE[layer]));
      for (const area of [...new Set(mine.filter((p) => p.layer === layer).map((p) => p.area))].sort()) {
        write(`${dir}/${ISSUER_LAYER_DIR[layer]}/${area}/index.md`, areaPage(ISSUER_LAYER_TITLE[layer], issuerAreaTitle(area)));
      }
    }
  }

  const technology = [...new Set(definitions.flatMap((d) => d.technology))];
  const unknownTechnology = technology.filter((line) => !ISSUER_TECHNOLOGY[line]);
  if (unknownTechnology.length) throw new Error(`no surrogate ICS item for the technology ${unknownTechnology.join(', ')} (ISSUER_TECHNOLOGY)`);
  write('ics-issuer.md', renderIssuerIcs(pages.ics, technology));

  write('defaults.md', `${trimNewlines(fromRp('defaults.md'))}\n\n${pages.defaults}`);
  write('references.md', `${trimNewlines(fromRp('references.md'))}\n${pages.references}`);
  let nav = insertAt(fromRp('.nav.yml'), '      - Shared: suts/shared/index.md\n', issuerNav(), 'before');
  nav = insertAt(nav, '  - ICS (Relying Party): ics-rp.md\n', '  - ICS (PID and Attestation Provider): ics-issuer.md\n', 'after');
  write('.nav.yml', nav);
  write(
    'suts/index.md',
    insertAt(
      fromRp('suts/index.md'),
      '(relying_party/index.md).\n',
      '\nDraft **PID Provider** and **Attestation Provider** SUTs are defined in addition: see [PID Provider (SUT)](pid_provider/index.md) and [Attestation Provider (SUT)](attestation_provider/index.md).\n',
      'after',
    ),
  );
  return files;
}
