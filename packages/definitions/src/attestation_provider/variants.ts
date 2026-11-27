// RP_AP: the Relying Party towards Attestation Providers (catalogue section 2.1): "Same objectives as `RP_PP` for QEAA,
// PuB-EAA and non-qualified EAA. Defined once in `RP_PP`; every `RP_PP_*` objective applies to `RP_AP` with the same
// number and the category variant `Q`, `PB` or `E`." The `RP_AP` definitions are derived from the `RP_PP` ones, which
// stay the source: the same steps, faults and expected results, with `default_credential_A` issued by the entity of the
// category (`QP-A`, `PB-A`, `EP-A`) and presented for the category's default query. What changes with the category is
// the root of trust of the status list (catalogue section 3.2, decision 3) and what `NOSTAT` means (decision 2: the
// policy the Relying Party declares in RP.R.2 instead of a rejection).
import {
  attestation,
  ATTESTATION_VARIANT_CATEGORY,
  type AttestationVariant,
  attestationTestCaseId,
  type CredentialCategory,
  type CredentialSpec,
  defineTestCase,
  type Expectation,
  formats,
  ics,
  type IcsCondition,
  item,
  queryOf,
  rej,
  type StepAction,
  type StepDefinition,
  type TestCaseDefinition,
} from '@eudi-pcaf/core';

interface CategoryWording {
  category: Exclude<CredentialCategory, 'pid'>;
  /** The kind of attestation, as a text names it. */
  name: string;
  article: 'a' | 'an';
  credential: string;
  query: string;
  /** The entity of `default_trust_configuration_rp` that issues the category's default credential. */
  entity: string;
  /** The anchor the entity's status lists are signed under (catalogue section 3.2). */
  anchor: string;
  profile: IcsCondition;
  /** The positive control of the category: `RP_WS_IA_MainInteraction_002` to `_004`. */
  controlNumber: number;
  /** The ARF requirement on the notification of the entity's anchors, if the category has one. */
  notification?: string;
  /** The specification of the list the entity is on, if the category has one. */
  list?: string;
}

const CATEGORIES: Record<AttestationVariant, CategoryWording> = {
  Q: {
    category: 'qeaa',
    name: 'QEAA',
    article: 'a',
    credential: item('default_credential_qeaa'),
    query: item('default_query_qeaa'),
    entity: '`QP-A`',
    anchor: 'the anchor of the granted qualified EAA service of `QP-A` in `TL-QEAA`',
    profile: ics.requestsQeaa,
    controlNumber: 2,
    list: '[ETSI TS 119 612]',
  },
  PB: {
    category: 'pub-eaa',
    name: 'PuB-EAA',
    article: 'a',
    credential: item('default_credential_pubeaa'),
    query: item('default_query_pubeaa'),
    entity: '`PB-A`',
    anchor: 'the PubEAA/Revocation anchor of `PB-A` in `TL-PUB`',
    profile: ics.requestsPubEaa,
    controlNumber: 3,
    notification: 'PuBPNot_06',
    list: '[ETSI TS 119 602]',
  },
  E: {
    category: 'eaa',
    name: 'non-qualified EAA',
    article: 'a',
    credential: item('default_credential_eaa'),
    query: item('default_query_eaa'),
    entity: '`EP-A`',
    anchor: 'the anchor `CA-EP-A` that the rulebook of `default_credential_eaa` defines',
    profile: ics.requestsEaa,
    controlNumber: 4,
  },
};

export const ATTESTATION_VARIANTS = Object.keys(CATEGORIES) as AttestationVariant[];

/**
 * `RP_PP` objectives without an `RP_AP` counterpart. `_011_UF` presents a status list signed under `PP-A`'s issuance
 * anchor, which `TL-PID` does not publish under its PID/Revocation service; no attestation category separates the two
 * anchors (`TL-QEAA` and the rulebook have one anchor per entity, and `PB-A` lists the same anchor under its
 * PubEAA/Issuance and PubEAA/Revocation services), so the stimulus has no wrong anchor to use.
 */
export const NOT_APPLICABLE = new Set(['RP_PP_SM_Revocation_011a_UF', 'RP_PP_SM_Revocation_011b_UF']);

const PID_CONTROL = /`RP_WS_IA_MainInteraction_001([ab])`/g;
const controlOf = (w: CategoryWording, letter: string) => `RP_WS_IA_MainInteraction_00${w.controlNumber}${letter}`;

const REJECTION =
  'its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx';
const STATUS_UNKNOWN = 'or it accepts the presentation and its verification result flags the revocation status as unknown (`status-unknown`)';
const REJ_TEXT = rej().text;
/** `NOSTAT` for an attestation (decision 2): the policy the Relying Party declares in RP.R.2. */
const NOSTAT_TEXT = `The Relying Party makes no positive status statement and handles the presentation as it declares in its ICS (RP.R.2): either it rejects the presentation (${REJECTION}), ${STATUS_UNKNOWN}.`;
/** The refusal of the freshness policy test case (`_014`), worded for an attestation. */
const POLICY_REFUSAL = `it makes no positive status statement: ${REJECTION}`;
const POLICY_REFUSAL_ATTESTATION = `it makes no positive status statement and handles the presentation as it declares in RP.R.2: it rejects it (${REJECTION}), ${STATUS_UNKNOWN}`;

/** Rewords a text of an `RP_PP` test case for the category. */
export function reword(text: string, w: CategoryWording): string {
  return text
    .replaceAll('`default_credential_pid`', w.credential)
    .replaceAll('`default_query_pid`', w.query)
    .replaceAll('a PID whose status', `${w.article} ${w.name} whose status`)
    .replaceAll('the revocation anchor of `PP-A`', w.anchor)
    .replace(PID_CONTROL, (_m, letter: string) => `\`${controlOf(w, letter)}\``);
}

const rewordReference = (reference: string, w: CategoryWording): string | undefined => {
  if (reference === '[ETSI TS 119 602]') return w.list;
  return reference.replace('PPNot_05, ', w.notification ? `${w.notification}, ` : '');
};

const rewordExpectation = (expect: Expectation, w: CategoryWording): Expectation => {
  let text = expect.text;
  if (expect.codes.includes('NOSTAT')) text = text.replace(REJ_TEXT, NOSTAT_TEXT);
  if (expect.policy?.item === 'RP.R.7' || expect.policy?.item === 'RP.R.8') text = text.replace(POLICY_REFUSAL, POLICY_REFUSAL_ATTESTATION);
  return { ...expect, text: reword(text, w) };
};

/** The attestation of the category in place of a PID: the same format, faults and (for `PP-A`) the category's issuer. */
const credentialOf = (credential: CredentialSpec, w: CategoryWording): CredentialSpec => {
  if (credential.defaultCredential !== 'default_credential_pid') throw new Error(`${credential.defaultCredential} has no attestation counterpart`);
  if (credential.issuer !== 'PP-A') throw new Error(`a PID issued by ${credential.issuer} has no attestation counterpart`);
  return attestation.of(w.category, credential.format, { faults: credential.faults });
};

const actionOf = (action: StepAction, w: CategoryWording): StepAction => {
  if (action.kind !== 'presentation') throw new Error(`an RP_PP step ${action.kind} has no attestation counterpart`);
  if (action.alongside?.length) throw new Error('a combined presentation has no attestation counterpart');
  const credential = credentialOf(action.credential, w);
  const signer = action.statusList?.signer;
  if (signer && signer.entity !== 'PP-A') throw new Error(`a status list signed by ${signer.entity} has no attestation counterpart`);
  return {
    ...action,
    query: queryOf(w.category, credential.format),
    credential,
    ...(action.statusList && signer ? { statusList: { ...action.statusList, signer: { ...signer, entity: credential.issuer } } } : {}),
  };
};

const stepOf = (step: StepDefinition, w: CategoryWording): StepDefinition => ({
  ...step,
  text: reword(step.text, w),
  ...(step.run ? { run: actionOf(step.run, w) } : {}),
  expect: rewordExpectation(step.expect, w),
});

/**
 * `_010`: the `RP_PP` test case presents a PID of `PP-A`, whose revocation anchor is separate, and one of `PP-B`, whose
 * status list is signed with the credential's own key. The entity of every attestation category signs its status lists
 * under its issuance anchor, so both steps present the category's credential: a status list signed by the status list
 * signer under that anchor, and one signed with the key and certificate of the credential.
 */
function signerUnderAnchor(definition: TestCaseDefinition, w: CategoryWording): Partial<TestCaseDefinition> | undefined {
  if (!/^RP_PP_SM_Revocation_010[ab]$/.test(definition.id)) return undefined;
  const [first, second] = definition.steps;
  if (!first?.run || first.run.kind !== 'presentation' || !second?.run || second.run.kind !== 'presentation') throw new Error(`${definition.id}: unexpected steps`);
  const ownKey = actionOf({ ...second.run, credential: { ...second.run.credential, issuer: 'PP-A' }, statusList: second.run.statusList && { ...second.run.statusList, signer: { entity: 'PP-A', key: 'issuance' } } }, w);
  const presents = `Perform a presentation for ${w.query} in which the Conformance Wallet presents ${w.credential} in a valid Authorization Response, while the Test Status Provider serves a valid Status List Token for it that holds the value 0x00 at the credential's index and is signed`;
  return {
    steps: [
      { ...stepOf(first, w), text: `${presents} by a certificate under ${w.anchor}.` },
      { text: `${presents} with the same key and certificate as that credential.`, run: ownKey, expect: rewordExpectation(second.expect, w) },
    ],
    comments: [
      `${w.entity} signs its credentials and its status lists under the same anchor, so in the second step the credential's own certificate is under ${w.anchor} ([Token Status List] section 11.3).`,
      ...(definition.comments ?? []).filter((c) => !c.includes('`PP-B`')),
    ],
  };
}

/** The variant of an `RP_PP` definition for category `variant`. */
export function attestationVariant(definition: TestCaseDefinition, variant: AttestationVariant): TestCaseDefinition {
  const w = CATEGORIES[variant];
  const letter = /_\d{3}([ab])(_UF)?$/.exec(definition.id)?.[1] ?? formats.mdoc.letter;
  const profile = definition.profile.map((c) => (c.item === ics.checksPidRevocation.item ? ics.checksAttestationRevocation : c));
  if (!definition.profile.some((c) => c.item === ics.checksPidRevocation.item)) throw new Error(`${definition.id} does not depend on RP.R.1`);
  const controls = definition.control === undefined ? [] : Array.isArray(definition.control) ? definition.control : [definition.control];
  if (controls.some((c) => c !== `RP_WS_IA_MainInteraction_001${letter}`)) throw new Error(`${definition.id}: unexpected positive control`);
  const special = signerUnderAnchor(definition, w);
  return defineTestCase({
    ...definition,
    id: attestationTestCaseId(definition.id, variant),
    objective: reword(definition.objective, w),
    references: definition.references.flatMap((r) => rewordReference(r, w) ?? []),
    profile: [profile[0], w.profile, ...profile.slice(1)],
    preconditions: definition.preconditions.map((p) => reword(p, w)),
    ...(controls.length ? { control: controlOf(w, letter) } : {}),
    steps: special?.steps ?? definition.steps.map((s) => stepOf(s, w)),
    ...(definition.comments ? { comments: special?.comments ?? definition.comments.map((c) => reword(c, w)) } : {}),
  });
}

/** The `Q`, `PB` and `E` variants of every `RP_PP` definition that has an `RP_AP` counterpart, by number and format. */
export function attestationVariants(definitions: TestCaseDefinition[]): TestCaseDefinition[] {
  return definitions
    .filter((d) => d.id.startsWith('RP_PP_') && !NOT_APPLICABLE.has(d.id))
    .flatMap((d) => ATTESTATION_VARIANTS.map((variant) => attestationVariant(d, variant)));
}
