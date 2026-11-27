// PP_WS_SM_Revocation_004 to _010 (issue 26; issuer catalogue section 5.1.3, `SCN-L`): revocation of the logical PID,
// suspension, revocation chaining when the Test Wallet Provider revokes the Wallet Instance or the WSCD, the change of
// subject data, and status that must stay unchanged. `_001` to `_003` are in Revocation.ts (issue 22). The catalogue
// names no format for these test cases, so each runs in `SD` and `MD`; the grant does not change what is published, so
// each runs in `PA` (`AC` follows with the authorization code flow), except `_004`, whose logical PID spans both formats.
import { defineIssuerTestCase, type FormatVariant, issuerProfiles, relevancy, type WalletEventAction } from '@eudi-pcaf/core';
import { published } from '../../status';
import { revokedWithin, unchangedFor, unitIssuance } from '../../inspection';
import { configurationOf, FORMAT_NAMES, iss, issuance, pidProfile, preconditions, technologyOf } from '../../wording';
import { rejected } from './attestations';

const FORMATS: FormatVariant[] = ['SD', 'MD'];
const hookPrecondition = 'The adapter can revoke, suspend and reinstate an issued credential and report when it has done so (ICS-06, `P-HOOK`); `T_rev` is declared, at most 24 hours (decision 3).';
const LONG_RUNNING = 'Long running: the steps that wait run after the other test cases, in parallel (issuer harness design section 6.3). The nightly job runs with declared values of minutes (decision 3).';

const setStatus = (status: 'revoked' | 'suspended' | 'valid', ofStep: number, what = `the credential of step ${ofStep}`) => ({
  text: `The adapter ${status === 'revoked' ? 'revokes' : status === 'suspended' ? 'suspends' : 'reinstates'} ${what} (\`setStatus\` ${status}) and reports when the Provider has done so (\`OBS-ADM\`).`,
  run: { kind: 'issuer-event' as const, event: 'set-status' as const, status, ofStep },
  expect: { codes: ['INFO' as const], text: 'The time the adapter reports is recorded; the window of the next step counts from it.' },
});

const timedStatus = (check: 'sl-suspended' | 'sl-reinstated', ofStep: number) => ({
  text: `The harness polls the status list of the credential of step ${ofStep} anonymously every \`min(T_rev / 20, 30 s)\` until \`T_rev\` (ICS-06) after the reported event, keeping every version.`,
  run: { kind: 'observe-status' as const, ofSteps: [ofStep], t: 'T_rev' },
  expect: published(
    [check],
    check === 'sl-suspended'
      ? "No later than `T_rev` after the reported suspension, a version of the list shows the credential's entry as `0x02` (SUSPENDED), and every later version polled shows it as `0x02` too."
      : "No later than `T_rev` after the reported reinstatement, a version of the list shows the credential's entry as `0x00` (VALID) again, and every later version polled shows it as `0x00` too.",
  ),
});

const walletEvent = (text: string, run: WalletEventAction) => ({ text, run, expect: { codes: ['INFO' as const], text: 'What the Test Wallet Provider served, and when, is recorded.' } });

/** The `SL-WP-A` version of the test case that the WIA (or KA) of the following issuance refers to. */
const ownList = (of: 'wia' | 'ka') =>
  walletEvent(
    `The Test Wallet Provider serves \`SL-WP-A\` for this test case under a URL of its own, every entry valid, and the ${of === 'wia' ? 'WIA' : 'KA'} of \`CW-1\` in the following steps refers to it with the unit's ${of === 'wia' ? 'Wallet Instance' : 'WSCD'} entry (a Provider may keep a fetched list for its \`ttl\`, so a shared list could mask the change).`,
    { kind: 'wallet-event', event: 'status-list', walletUnit: 'CW-1', statusList: { id: 'SL-WP-A', faults: [], of } },
  );

const revocation004 = () =>
  defineIssuerTestCase({
    id: 'PP_WS_SM_Revocation_004',
    variants: ['PA'],
    objective: 'Verify that revoking the logical PID revokes every technical credential of it: each credential of a batch, in both formats.',
    references: ['[ARF] Annex 2, VCR_07a', '[ARF] Annex 2, PAD_02', '[TokenStatusList] section 7.1'],
    profile: [issuerProfiles['P-PID'], issuerProfiles['P-SD'], issuerProfiles['P-MD'], issuerProfiles['P-PA'], issuerProfiles['P-BATCH'], issuerProfiles['P-REV'], issuerProfiles['P-HOOK']],
    relevancy: relevancy.specificRequired,
    technology: ['OpenID4VCI', 'SD-JWT VC', 'ISO/IEC 18013-5 mdoc', 'Token Status List'],
    preconditions: [...preconditions.base, hookPrecondition, 'The Provider issues in batches (ICS-08, `P-BATCH`) of at least 2.'],
    steps: [
      {
        text: 'The adapter creates one credential offer for `SUBJ-1` and the PID configurations in SD-JWT VC and mdoc format, pre-authorized code. `CW-1` runs `SCN-I` without mutation, with 2 proofs over the keys of one KA in each credential request: the technical credentials of one logical PID, in both formats and in a batch.',
        run: issuance('SD', 'PA', { configurations: [configurationOf('SD'), configurationOf('MD')], batchSize: 2 }),
        expect: { codes: ['ISS'], text: 'The Provider issues every credential (HTTP 200), two per format. Every credential passes the checks of `ISS` (section 2.5).' },
      },
      unchangedFor([1], 'PT0S', 'once, before the revocation'),
      setStatus('revoked', 1, 'the logical PID of step 1'),
      revokedWithin([1], 'T_rev', 'the reported revocation'),
    ],
    comments: [
      LONG_RUNNING,
      'The logical PID spans both formats and a batch, so a single definition covers both stimuli of the catalogue ("one credential of a batch, or one format").',
      'The batch is valid: the issuance client adds one proof per further key of the KA (issue 26); the batch faults are issue 25.',
    ],
  });

const revocation005 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SM_Revocation_005',
    variants: [format, 'PA'],
    objective: `Verify that suspending a ${FORMAT_NAMES[format]} PID sets the suspended value in the published list, reinstating it clears it, and a revocation after the suspension is final.`,
    references: ['[TokenStatusList] section 7.1', '[ARF] Annex 2, VCR_04'],
    profile: [...pidProfile(format, 'PA'), issuerProfiles['P-REV'], issuerProfiles['P-SUSP'], issuerProfiles['P-HOOK']],
    relevancy: relevancy.specificOptional,
    technology: [...technologyOf(format), 'Token Status List'],
    preconditions: [...preconditions.base, hookPrecondition, 'The Provider supports suspension (ICS-05, `P-SUSP`): its status lists have at least 2 bits per entry.'],
    steps: [
      unitIssuance(format),
      setStatus('suspended', 1),
      timedStatus('sl-suspended', 1),
      setStatus('valid', 1),
      timedStatus('sl-reinstated', 1),
      setStatus('revoked', 1),
      revokedWithin([1], 'T_rev', 'the reported revocation'),
    ],
    comments: [LONG_RUNNING, '"Final" is checked over every version polled until `T_rev` has passed; `PP_TB_003` covers the policy that a revocation is never reversed.'],
  });

const chaining = (id: 'PP_WS_SM_Revocation_006' | 'PP_WS_SM_Revocation_007', format: FormatVariant) => {
  const of = id === 'PP_WS_SM_Revocation_006' ? 'wia' : 'ka';
  const what = of === 'wia' ? 'the Wallet Instance' : 'the WSCD';
  return defineIssuerTestCase({
    id,
    variants: [format, 'PA'],
    objective: `Verify revocation chaining: when the Test Wallet Provider revokes ${what} of \`CW-1\` in \`SL-WP-A\` (${of === 'wia' ? 'the WIA' : 'the KA'} status), the PID in ${FORMAT_NAMES[format]} format issued to it is revoked within \`T_chain\`.`,
    references: ['[ARF] Annex 2, WURevocation_18', '[ARF] Annex 2, WUA_29', ...(of === 'wia' ? ['[ARF] Annex 2, VCR_07c'] : []), '[TS3] section 2.5'],
    profile: [...pidProfile(format, 'PA'), issuerProfiles['P-REV'], issuerProfiles['P-CHAIN']],
    relevancy: relevancy.specificRequired,
    technology: [...technologyOf(format), 'Token Status List'],
    preconditions: [
      ...preconditions.base,
      'The Provider is a PID Provider and chains revocation (ICS-07, `P-CHAIN`, mandatory for PID Providers); `T_chain` is declared, at most 24 hours (decision 3).',
    ],
    steps: [
      ownList(of),
      unitIssuance(format, 'CW-1', { why: `the ${of === 'wia' ? 'WIA' : 'KA'} refers to the list of step 1` }),
      unchangedFor([2], 'PT0S', 'once, before the revocation'),
      walletEvent(
        `The Test Wallet Provider revokes ${what} of \`CW-1\`: it serves a new version of the list of step 1, under the same URL, with the unit's ${of === 'wia' ? 'Wallet Instance' : 'WSCD'} entry \`0x01\` (INVALID) and every other entry unchanged.`,
        { kind: 'wallet-event', event: of === 'wia' ? 'revoke-instance' : 'revoke-wscd', walletUnit: 'CW-1' },
      ),
      revokedWithin([2], 'T_chain', `the revocation of ${what}`),
    ],
    comments: [
      LONG_RUNNING,
      `The WIA and KA carry their status as TS3 defines it: \`client_status.status.status_list\` (WIA) and \`key_storage_status.status.status_list\` (KA).`,
      '**PID only** (catalogue): an Attestation Provider declares whether it chains (WURevocation_19).',
    ],
  });
};

const revocation008 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SM_Revocation_008',
    variants: [format, 'PA'],
    objective: `Verify that when the subject's data change while the ${FORMAT_NAMES[format]} PID has more than 24 hours left, the old PID is revoked within \`T_rev\` and a new issuance gives the new values.`,
    references: ['[ARF] Annex 2, VCR_09', '[ARF] Annex 2, ISSU_62'],
    profile: [...pidProfile(format, 'PA'), issuerProfiles['P-REV'], issuerProfiles['P-HOOK']],
    relevancy: relevancy.specificRequired,
    technology: [...technologyOf(format), 'Token Status List'],
    preconditions: [
      ...preconditions.base,
      'The adapter seeds `SUBJ-1` and `SUBJ-2` (ICS-17) and can replace the data of `SUBJ-1` by those of `SUBJ-2` (`changeSubject`, ICS-06); NOT APPLICABLE otherwise (decision 5).',
    ],
    steps: [
      unitIssuance(format),
      {
        text: 'The adapter replaces the data of `SUBJ-1` by those of `SUBJ-2` (`changeSubject`), as a change in the Provider\'s source of identity data; the time it reports counts as `OBS-ADM`.',
        run: { kind: 'issuer-event', event: 'change-subject', from: 'SUBJ-1', to: 'SUBJ-2' },
        expect: { codes: ['INFO'], text: 'The time the adapter reports is recorded; the window of the next step counts from it.' },
      },
      revokedWithin([1], 'T_rev', 'the reported change'),
      {
        text: `The adapter creates a credential offer for \`SUBJ-1\` again, PID configuration in ${FORMAT_NAMES[format]} format; \`CW-1\` runs \`SCN-I\` without mutation.`,
        run: issuance(format, 'PA'),
        expect: { ...iss(format), codes: ['CONF'], checks: ['pid-values'], text: `${iss(format).text} \`pid-values\`: every PID attribute has the value of \`SUBJ-2\`, the subject's data after the change.` },
      },
    ],
    comments: [LONG_RUNNING, 'The test case runs alone, after every other one, since the change of `SUBJ-1` affects every credential issued for it.', 'The PID of step 1 lives longer than 24 hours (ICS-05.validity_period).'],
  });

const revocation009 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SM_Revocation_009',
    variants: [format, 'PA'],
    objective: `Verify that revoking one ${FORMAT_NAMES[format]} PID changes the status of no other credential: neither another logical PID of the same Wallet Unit nor the PID of another Wallet Unit.`,
    references: ['[TokenStatusList] section 4'],
    profile: [...pidProfile(format, 'PA'), issuerProfiles['P-REV'], issuerProfiles['P-HOOK']],
    relevancy: relevancy.genericRequired,
    technology: [...technologyOf(format), 'Token Status List'],
    preconditions: [...preconditions.base, hookPrecondition, 'Wallet Unit `CW-2` of `WP-A` (section 3.4).'],
    steps: [
      unitIssuance(format, 'CW-1', { why: 'the PID that is revoked' }),
      unitIssuance(format, 'CW-1', { why: 'a second logical PID of the same Wallet Unit' }),
      unitIssuance(format, 'CW-2', { why: 'the PID of another Wallet Unit' }),
      unchangedFor([1, 2, 3], 'PT0S', 'once, before the revocation'),
      setStatus('revoked', 1),
      revokedWithin([1], 'T_rev', 'the reported revocation'),
      unchangedFor([2, 3], 'T_rev', 'once more after `T_rev` has passed since the revocation, when step 6 has seen it published'),
    ],
    comments: [LONG_RUNNING],
  });

const revocation010 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SM_Revocation_010',
    variants: [format, 'PA'],
    objective: `Verify that unrelated events, a failed issuance and an outage of the WIA status list, do not revoke an issued ${FORMAT_NAMES[format]} PID.`,
    references: ['[ARF] Annex 2, PAD_03', '[ARF] Annex 2, VCR_05'],
    profile: [...pidProfile(format, 'PA'), issuerProfiles['P-REV']],
    relevancy: relevancy.specificOptional,
    technology: [...technologyOf(format), 'Token Status List'],
    preconditions: [...preconditions.base, '`T_chain` is declared (ICS-07): a Provider that chains revocation reads the WIA status within it.'],
    steps: [
      ownList('wia'),
      unitIssuance(format, 'CW-1', { why: 'the WIA refers to the list of step 1' }),
      {
        text: `A failed issuance: the adapter creates a credential offer for \`SUBJ-1\`, PID configuration in ${FORMAT_NAMES[format]} format; \`CW-1\` runs \`SCN-I\` with one bit of the signature of its proof flipped (\`proof.signature-bitflip\`).`,
        run: issuance(format, 'PA', { faults: ['proof.signature-bitflip'] }),
        expect: rejected(),
      },
      walletEvent('An outage of the WIA status list: the URL of the list of step 1 answers HTTP 503 without a token from now on.', {
        kind: 'wallet-event',
        event: 'status-list',
        walletUnit: 'CW-1',
        statusList: { id: 'SL-WP-A', faults: [], of: 'wia', httpStatus: 503 },
      }),
      unchangedFor([2], 'T_chain', 'every `min(T_chain / 20, 30 s)` until `T_chain` (ICS-07) after the outage began'),
    ],
    comments: [
      LONG_RUNNING,
      'The notification `credential_deleted` (the third event of the catalogue) needs the notification step of issue 25 (`PP_WS_IA_Notification`); it is added to this test case when that step is on `main`.',
    ],
  });

export const definitions = [
  revocation004(),
  ...FORMATS.map(revocation005),
  ...FORMATS.map((f) => chaining('PP_WS_SM_Revocation_006', f)),
  ...FORMATS.map((f) => chaining('PP_WS_SM_Revocation_007', f)),
  ...FORMATS.map(revocation008),
  ...FORMATS.map(revocation009),
  ...FORMATS.map(revocation010),
];
