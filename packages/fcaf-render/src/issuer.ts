// Renders the issuer test cases (issuer harness design section 4, row `fcaf-render`, and decision 1): one FCAF test case
// page per test case ID of `@eudi-pcaf/issuer-definitions`. A test case has one definition per variant (format,
// grant, category; issuer catalogue section 2.3), and the FCAF has one file per ID, so the variants of an ID are merged
// into one page: what all of them share is rendered once, what differs is listed per variant.
import { parseIssuerTestCaseId, variantOf, type IssuerTestCaseDefinition } from '@eudi-pcaf/core';

/** The directory of the PID Provider SUT below `docs/fcaf`. */
export const PID_PROVIDER_DIR = 'suts/pid_provider';
/** Issue 27: the directory of the Attestation Provider SUT below `docs/fcaf` (issuer harness design section 10, I4). */
export const ATTESTATION_PROVIDER_DIR = 'suts/attestation_provider';

/** The SUTs of the issuer overlay: their directory, title and the prefix of their classes. */
export const ISSUER_SUTS = [
  { prefix: 'PP', dir: PID_PROVIDER_DIR, title: 'PID Provider (SUT)', page: 'pid-provider.md' },
  { prefix: 'AP', dir: ATTESTATION_PROVIDER_DIR, title: 'Attestation Provider (SUT)', page: 'attestation-provider.md' },
] as const;

/** The SUT directory of a class: `PP_*` the PID Provider, `AP_*` the Attestation Provider. */
export const sutDirOf = (sutClass: string) => (sutClass.startsWith('AP_') ? ATTESTATION_PROVIDER_DIR : PID_PROVIDER_DIR);

/** Class directories below each Provider SUT. */
export const ISSUER_CLASS_DIR: Record<string, string> = {
  PP_WS: 'wallet_solution',
  PP_RP: 'relying_party',
  PP_Inf: 'infrastructure',
  // Issue 27
  AP_WS: 'wallet_solution',
  AP_RP: 'relying_party',
  AP_Inf: 'infrastructure',
};
export const ISSUER_CLASS_TITLE: Record<string, string> = {
  PP_WS: 'PID Provider - Wallet Solution',
  PP_RP: 'PID Provider - Relying Party',
  PP_Inf: 'PID Provider - Trust Infrastructure',
  AP_WS: 'Attestation Provider - Wallet Solution',
  AP_RP: 'Attestation Provider - Relying Party',
  AP_Inf: 'Attestation Provider - Trust Infrastructure',
};
/** Navigation label and overview page of each class, as the RP overlay names its classes. */
export const ISSUER_CLASS_NAV: Record<string, { label: string; overview: string }> = {
  PP_WS: { label: '(pp_ws) Wallet Solution', overview: 'pp_ws.md' },
  PP_RP: { label: '(pp_rp) Relying Party', overview: 'pp_rp.md' },
  PP_Inf: { label: '(pp_inf) Trust Infrastructure', overview: 'pp_inf.md' },
  AP_WS: { label: '(ap_ws) Wallet Solution', overview: 'ap_ws.md' },
  AP_RP: { label: '(ap_rp) Relying Party', overview: 'ap_rp.md' },
  AP_Inf: { label: '(ap_inf) Trust Infrastructure', overview: 'ap_inf.md' },
};

/** Layers of the issuer catalogue section 2.1, which follow the FCAF. */
export const ISSUER_LAYER_DIR: Record<string, string> = { IA: 'Interaction', SM: 'SecurityMechanisms', MS: 'MessageStructure', DM: 'DataModel', SH: 'Shared' };
export const ISSUER_LAYER_TITLE: Record<string, string> = { IA: 'Interaction', SM: 'Security Mechanisms', MS: 'Message Structure', DM: 'Data Model', SH: 'Shared' };

/** Area titles that splitting the camel-case area name would get wrong. */
const ISSUER_AREA_TITLE: Record<string, string> = {
  PidSdJwt: 'PID in SD-JWT VC format',
  PidMdoc: 'PID in mdoc format',
  Portrait: 'PID portrait',
  PreAuthorized: 'Pre-Authorized Code',
  ProofOfPossession: 'Proof of Possession',
  // Issue 27
  Rulebook: 'Rulebook of the attestation',
};

/** The title of an area: `ClientAttestation` is "Client Attestation", unless `ISSUER_AREA_TITLE` names it. */
export function issuerAreaTitle(area: string): string {
  return ISSUER_AREA_TITLE[area] ?? area.replace(/([a-z])([A-Z])/g, '$1 $2');
}

/** Path of an issuer test case below the overlay root `docs/fcaf`. */
export function issuerTestCasePath(id: string): string {
  return `${sutDirOf(parseIssuerTestCaseId(id).sutClass)}/${issuerTestCasePathInSut(id)}`;
}

/** Path of an issuer test case below its SUT directory. */
export function issuerTestCasePathInSut(id: string): string {
  const { sutClass, layer, area } = parseIssuerTestCaseId(id);
  const classDir = ISSUER_CLASS_DIR[sutClass];
  const layerDir = ISSUER_LAYER_DIR[layer];
  if (!classDir || !layerDir) throw new Error(`${id}: no directory for class ${sutClass} or layer ${layer}`);
  return `${classDir}/${layerDir}/${area}/${id}.md`;
}

/** The definitions grouped by test case ID, in the order of their first definition; the variants in definition order. */
export function groupByTestCase(definitions: IssuerTestCaseDefinition[]): IssuerTestCaseDefinition[][] {
  const groups = new Map<string, IssuerTestCaseDefinition[]>();
  for (const definition of definitions) {
    const group = groups.get(definition.id);
    if (group) group.push(definition);
    else groups.set(definition.id, [definition]);
  }
  for (const [id, group] of groups) {
    const variants = group.map(variantOf);
    const twice = variants.filter((v, i) => variants.indexOf(v) !== i);
    if (twice.length) throw new Error(`${id}: variant ${twice.join(', ')} is defined twice`);
  }
  return [...groups.values()];
}

const numbered = (items: string[]) => items.map((text, i) => `${i + 1}. ${text}`).join('\n');
const bullets = (items: string[]) => items.map((text) => `- ${text}`).join('\n');
const unique = (items: string[]) => [...new Set(items)];
const code = (text: string) => `\`${text}\``;
/** Nested list items below a numbered item: four spaces, as Python-Markdown needs them. */
const NESTED = '    ';

/**
 * One text per variant, merged: the text when every variant has the same, else one item per distinct text with the
 * variants that have it, in the order they first appear.
 */
function perVariant(texts: string[], variants: string[]): { same: true; text: string } | { same: false; items: string[] } {
  const distinct = unique(texts);
  if (distinct.length === 1) return { same: true, text: distinct[0] };
  return { same: false, items: distinct.map((text) => `${variants.filter((_, i) => texts[i] === text).map(code).join(', ')}: ${text}`) };
}

/** A section that every variant has, as paragraphs: one paragraph, or a list with one item per variant. */
function mergedParagraph(texts: string[], variants: string[]): string {
  const merged = perVariant(texts, variants);
  return merged.same ? merged.text : bullets(merged.items);
}

/** Test Scenario or Expected results: one numbered item per step, with one nested item per variant where they differ. */
function mergedSteps(steps: string[][], variants: string[]): string {
  return numbered(
    steps[0].map((_, index) => {
      const merged = perVariant(
        steps.map((s) => s[index]),
        variants,
      );
      return merged.same ? merged.text : `Per variant:\n${merged.items.map((item) => `${NESTED}- ${item}`).join('\n')}`;
    }),
  );
}

/** The fields the variants of a test case must share, since the page renders them once. */
const SHARED_FIELDS = ['references', 'relevancy', 'preconditions', 'comments'] as const;

/**
 * The FCAF markdown of one issuer test case from its definitions, one per variant. Objective, technology, profile
 * applicability and the steps may differ between variants; the other fields and the number of steps may not.
 */
export function renderIssuerTestCase(group: IssuerTestCaseDefinition[]): string {
  const [first] = group;
  if (group.some((d) => d.id !== first.id)) throw new Error(`${first.id}: definitions of several test cases in one group`);
  for (const field of SHARED_FIELDS) {
    if (unique(group.map((d) => JSON.stringify(d[field] ?? null))).length > 1) throw new Error(`${first.id}: the variants differ in ${field}`);
  }
  if (unique(group.map((d) => String(d.steps.length))).length > 1) throw new Error(`${first.id}: the variants have different numbers of steps`);
  const variants = group.map(variantOf);

  const parts = [`# ${first.id}`, '## Objective', mergedParagraph(group.map((d) => d.objective), variants), '## References', bullets(first.references)];
  const profile = unique(group.flatMap((d) => d.profile.map((p) => p.text)));
  parts.push('## Profile applicability', profile.length ? bullets(profile) : 'None');
  parts.push('## EUDI-wallet relevancy', first.relevancy);
  const technology = unique(group.flatMap((d) => d.technology));
  if (technology.length) parts.push('## Technology', bullets(technology));
  parts.push('## Preconditions', first.preconditions.length ? numbered(first.preconditions) : 'None');
  parts.push('## Test Scenario', mergedSteps(group.map((d) => d.steps.map((s) => s.text)), variants));
  parts.push('## Expected results', mergedSteps(group.map((d) => d.steps.map((s) => s.expect.text)), variants));
  const comments = [...(first.comments ?? [])];
  if (first.variants) comments.push(variantsComment(group));
  if (comments.length) parts.push('## Comments', comments.join('\n\n'));
  return `${parts.join('\n\n')}\n`;
}

/** The variants of a test case with the Provider profiles each one needs (issuer catalogue sections 2.3 and 4). */
function variantsComment(group: IssuerTestCaseDefinition[]): string {
  const items = group.map((d) => `${code(variantOf(d))} (${d.profile.map((p) => code(p.equals)).join(', ')})`);
  if (items.length === 1) return `Variant ${items[0]} (issuer catalogue section 2.3); it applies when the Provider's ICS puts it in these profiles.`;
  return `Variants (issuer catalogue section 2.3), each executed when the Provider's ICS puts it in the profiles named: ${items.join(', ')}.`;
}
