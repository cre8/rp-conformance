// RP_Inf_SM_TrustMechanisms: the Relying Party's processing of the trust lists themselves. A new version of `TL-PID`
// (or of `TL-QEAA`) is published and the Relying Party retrieves it; a version it must not use adds an entity, so a
// Relying Party that uses it anyway accepts that entity's credential. Not written: `_007` (changes reach every Relying
// Party Instance; the harness observes one), and `_010` and `_011`, which other test cases cover
// (RP_WS_SM_TrustMechanisms_002, _003, _013; RP_PP_SM_Revocation_009, _010).
import {
  acc,
  all,
  attestation,
  comments,
  credentials,
  defineTestCase,
  type FaultId,
  faultInfo,
  formats,
  ics,
  type IcsCondition,
  listRetrieved,
  PID,
  pid,
  positiveControlOf,
  preconditions,
  presentation,
  presentationStep,
  queries,
  rej,
  relevancy,
  scenario,
  stale,
  type StepDefinition,
  step,
  type TrustListAction,
  testCaseId,
} from '@eudi-pcaf/core';

const CONTROLS: [string, string] = [positiveControlOf(formats.sdJwtVc), positiveControlOf(formats.mdoc)];
const LOTE = ['[ETSI TS 119 602]', '[ARF] Annex 2, OIA_15a, OIA_15b'];
const TL = ['[ETSI TS 119 612] Annex A', '[ARF] Annex 2, OIA_13, OIA_15b'];
const WAIT = 'Wait until the Relying Party has retrieved it, at most `T_refresh`.';
const LAST_VALID =
  'The new version adds an entity, so a Relying Party that used it would accept that entity\'s credential. Whether the last valid version then stays in use (until its `NextUpdate` plus the grace period `G`) is the policy the Relying Party declares in RP.T.4.';
const CREDENTIAL_FORMAT = 'The credential format does not affect this test case; use the credentials in a format the Relying Party requests.';

interface InfCase {
  number: number;
  unhappyFlow?: boolean;
  objective: string;
  references: string[];
  profile?: IcsCondition[];
  preconditions?: string[];
  steps: StepDefinition[];
  comments?: string[];
}

const trustMechanisms = (testCase: InfCase) =>
  defineTestCase({
    id: testCaseId('Inf', 'SM', 'TrustMechanisms', testCase.number, '', testCase.unhappyFlow ?? true),
    objective: testCase.objective,
    references: testCase.references,
    profile: testCase.profile ?? [],
    relevancy: relevancy.specificRequired,
    technology: [],
    preconditions: [...preconditions.base, preconditions.controlOfFlow(CONTROLS), ...(testCase.preconditions ?? [])],
    control: CONTROLS,
    steps: testCase.steps,
    comments: [
      ...(testCase.comments ?? []),
      testCase.profile?.includes(ics.requestsQeaa) ? 'Restore the previous version of `TL-QEAA` after the test case.' : comments.restoreTrustList,
      CREDENTIAL_FORMAT,
      comments.flow,
    ],
  });

/** A new version of a list, with its changes and at most one trust-list fault, and the wait for its retrieval. */
const publish = (text: string, action: Omit<TrustListAction, 'kind'>): StepDefinition => {
  const faults = action.faults ?? [];
  if (faults.length > 1) throw new Error(`a step applies one fault, not ${faults.join(', ')}`);
  for (const fault of faults) {
    const info = faultInfo(fault);
    if (info.point !== 'trust-list' || info.format !== (action.list === 'TL-QEAA' ? 'trusted-list' : 'lote')) throw new Error(`fault ${fault} does not apply to ${action.list}`);
  }
  const difference = faults.length ? ` It is valid in every other respect, except that ${faultInfo(faults[0] as FaultId).text}.` : '';
  return step({ text: `${text}${difference} ${WAIT}`, run: { kind: 'trust-list', ...action }, expect: listRetrieved(action.list) });
};

/** The version of `TL-PID` that adds an entry for `PP-C`, with a fault. */
const addingPpC = (fault?: FaultId) =>
  publish('The Test Trust Infrastructure publishes a new version of `TL-PID` that adds an entry for `PP-C` with a granted PID/Issuance and PID/Revocation service.', {
    list: 'TL-PID',
    add: ['PP-C'],
    ...(fault ? { faults: [fault] } : {}),
  });

const pidOf = (issuer: string, expect: 'ACC' | 'REJ') =>
  step({
    ...presentationStep.credentialVariant(`it is issued by \`${issuer}\``, { credential: pid.sdJwtVc({ issuer }) }),
    expect: expect === 'ACC' ? acc() : rej(),
  });
const validPid = () => step({ ...presentationStep.valid({ credential: pid.sdJwtVc() }), expect: acc({ credential: PID }) });
/** The valid PID after a version of `TL-PID` that failed its seal: as the Relying Party declares in RP.T.4. */
const validPidAfterBadSeal = () =>
  step({
    ...presentationStep.valid({ credential: pid.sdJwtVc() }),
    expect: {
      codes: ['POLICY'],
      policy: { item: 'RP.T.4' },
      text: 'As the Relying Party declares in RP.T.4: `Keep` accepts the presentation and releases exactly the requested attributes (the last valid version of `TL-PID` stays in use); `Discard` rejects it (no usable `TL-PID`).',
    },
  });
const KEEP_OR_DISCARD =
  'Step 3 is `POLICY` (RP.T.4) since the spec review of 2026-11-20 (catalogue section 9): ETSI TS 119 602 and the ARF require the seal of a list to be verified before it is used, but no specification requires a Relying Party to keep the last valid version, so discarding the list (fail-closed) conforms too.';

const qeaaOfQpN = (expectAccepted: boolean) =>
  step({
    text: scenario.credentialVariant('it is issued by `QP-N`', { credential: credentials.qeaa, query: queries.qeaa }),
    run: presentation({ query: 'default_query_qeaa', credential: attestation.of('qeaa', 'dc+sd-jwt', { issuer: 'QP-N' }) }),
    expect: expectAccepted ? acc({ credential: `${credentials.qeaa} issued by \`QP-N\``, query: queries.qeaa }) : rej(),
  });

const grantingQpN = (fault?: FaultId) =>
  publish('The Test Trust Infrastructure publishes a new version of `TL-QEAA` in which the service of `QP-N` is a granted qualified service for the issuance of QEAAs.', {
    list: 'TL-QEAA',
    grantQualified: ['QP-N'],
    ...(fault ? { faults: [fault] } : {}),
  });

export const definitions = [
  trustMechanisms({
    number: 1,
    unhappyFlow: false,
    objective: 'Verify that the Relying Party loads a new version of the PID Provider list, validates its seal with the configured scheme operator certificate, and uses its anchors.',
    references: [...LOTE, '[ARF] Annex 2, TLPub_05, TLPub_07'],
    steps: [addingPpC(), pidOf('PP-C', 'ACC')],
  }),
  trustMechanisms({
    number: 2,
    objective: 'Verify that the Relying Party does not use a version of the PID Provider list whose seal is invalid, and then acts as it declares (RP.T.4): it keeps the last valid version, or uses none.',
    references: LOTE,
    steps: [addingPpC('trust-list.seal-bitflip'), pidOf('PP-C', 'REJ'), validPidAfterBadSeal()],
    comments: [LAST_VALID, KEEP_OR_DISCARD],
  }),
  trustMechanisms({
    number: 3,
    objective: 'Verify that the Relying Party does not use a version of the PID Provider list sealed by a key other than that of its scheme operator, and then acts as it declares (RP.T.4): it keeps the last valid version, or uses none.',
    references: LOTE,
    steps: [addingPpC('trust-list.sealed-by-ca-x'), pidOf('PP-C', 'REJ'), validPidAfterBadSeal()],
    comments: [LAST_VALID, KEEP_OR_DISCARD],
  }),
  trustMechanisms({
    number: 4,
    unhappyFlow: false,
    objective: 'Verify that the Relying Party keeps using a PID Provider list whose `NextUpdate` has passed during the grace period, and signals that it is stale.',
    references: [...LOTE, '[ARF] Annex 2, OIA_15a'],
    profile: [ics.appliesGracePeriod],
    steps: [
      addingPpC('trust-list.stale-within-grace'),
      step({
        ...presentationStep.credentialVariant('it is issued by `PP-C`', { credential: pid.sdJwtVc({ issuer: 'PP-C' }) }),
        expect: all(acc(), stale('TL-PID')),
      }),
    ],
    comments: [
      'The harness cannot move the clock of the Relying Party, so it publishes a version whose `NextUpdate` has already passed: the state a list reaches when no newer version appears.',
    ],
  }),
  trustMechanisms({
    number: 5,
    objective: 'Verify that the Relying Party ignores a version of the PID Provider list that rolls back to an older one.',
    references: LOTE,
    steps: [
      publish('The Test Trust Infrastructure publishes a new version of `TL-PID` with the same entries.', { list: 'TL-PID' }),
      validPid(),
      publish('The Test Trust Infrastructure publishes a version of `TL-PID` that lists the PID/Issuance service of `PP-W` again.', {
        list: 'TL-PID',
        restoreIssuance: ['PP-W'],
        faults: ['trust-list.rollback'],
      }),
      pidOf('PP-W', 'REJ'),
    ],
    comments: [
      'Step 2 makes a Relying Party that retrieves lists only when it needs them load the version of step 1, so the version of step 3 rolls back from the one in use.',
      'The rolled back version would make `PP-W` a PID Provider again, so a Relying Party that used it would accept its PID.',
    ],
  }),
  trustMechanisms({
    number: 6,
    objective: 'Record whether the Relying Party uses a list whose `LoTEType` is not that of a PID Providers list as the PID Provider list.',
    references: [...LOTE, '[ETSI TS 119 602] clause 6.3.3, Annexes D and E', '[ARF] Annex 2, OIA_15'],
    steps: [
      addingPpC('trust-list.wrong-type'),
      step({
        ...presentationStep.credentialVariant('it is issued by `PP-C`', { credential: pid.sdJwtVc({ issuer: 'PP-C' }) }),
        expect: {
          codes: ['INFO'],
          text: 'Whether the Relying Party accepts or rejects the PID of `PP-C` is recorded; HTTP 5xx fails.',
        },
      }),
    ],
    comments: [
      LAST_VALID,
      'Informational since the spec review of 2026-11-20 (catalogue section 8.3). The version is itself not a conforming list of either type: its `LoTEType` is that of a Wallet Providers list (ETSI TS 119 602 Annex E, Table E.1), while it carries PID Providers with PID/Issuance services (Annex D). The `LoTEType` "permits a parser to determine the form of any following field to expect" (clause 6.3.3); no clause requires a Relying Party to refuse a list fetched from the PID list location because of it. Nor does the type alone turn the entries into PID Providers: `PP-C` carries a PID/Issuance service in either case.',
    ],
  }),
  trustMechanisms({
    number: 8,
    unhappyFlow: false,
    objective: 'Verify that the Relying Party reaches the Trusted List of QTSPs through the list of trusted lists, validates it with the certificate of the pointer, and extracts the type and status of its services.',
    references: TL,
    profile: [ics.requestsQeaa],
    steps: [grantingQpN(), qeaaOfQpN(true)],
  }),
  trustMechanisms({
    number: 9,
    objective: 'Verify that the Relying Party does not use a Trusted List of QTSPs signed with a certificate that the pointer of the list of trusted lists does not name.',
    references: TL,
    profile: [ics.requestsQeaa],
    steps: [grantingQpN('trusted-list.signer-ca-x'), qeaaOfQpN(false)],
    comments: [
      'The catalogue expects the QEAA of `QP-A` to be rejected. A Relying Party keeps using the last valid version of the list, so the new version instead grants `QP-N` a qualified service, and the QEAA of `QP-N` stays rejected.',
    ],
  }),
  trustMechanisms({
    number: 12,
    objective: 'Verify that the Relying Party no longer uses a PID Provider list whose `NextUpdate` has passed by more than the grace period.',
    references: [...LOTE, '[ARF] Annex 2, OIA_15a'],
    steps: [addingPpC('trust-list.stale-after-grace'), pidOf('PP-C', 'REJ')],
    comments: [
      'The harness cannot move the clock of the Relying Party, so it publishes a version whose `NextUpdate` lies more than the grace period in the past: the state a list reaches when no newer version appears.',
    ],
  }),
];
