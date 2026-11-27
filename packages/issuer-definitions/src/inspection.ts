// Issue 26: building blocks of the test cases of `PP_WS_SM_IssuerIntegrity`, `PP_WS_SM_Unlinkability`,
// `PP_WS_SM_Revocation_004` to `_010` and `PP_Inf_SM_TrustMechanisms`: the `inspect` step with the wording of its
// checks, issuance steps of a Wallet Unit, the `trust-list` step, and the status steps of chaining and suspension.
import type { FormatVariant, GrantVariant, IssuanceAction, IssuerExpectation, IssuerInspectionCheck, IssuerStepDefinition, IssuerTrustListAction, WalletUnit } from '@eudi-pcaf/core';
import { faultInfo } from '@eudi-pcaf/core';
import { FORMAT_NAMES, GRANT_NAMES, iss, issuance } from './wording';

/** What each check of an `inspect` step establishes, as the FCAF text names it. */
export const INSPECTION_CHECK_TEXT: Record<IssuerInspectionCheck, string> = {
  'sd-jwt-typ': '`sd-jwt-typ` (the header carries `typ` `dc+sd-jwt`)',
  'signer-algorithm': '`signer-algorithm` (`alg` is `ES256`, `ES384` or `ES512`, ECCG agreed, with the signer key on its curve)',
  'signer-chain': '`signer-chain` (`x5c` or `x5chain` carries the signer certificate first and its intermediates in order, no self-issued trust anchor)',
  'mdoc-digest-algorithm': '`mdoc-digest-algorithm` (the MSO `digestAlgorithm` is `SHA-256`)',
  'signer-profile': '`signer-profile` (the signer certificate is one the Test Registrar enrolled for the Provider in the ETSI TS 119 412-6 profile: end-entity, `keyUsage` `digitalSignature` without certificate or CRL signing, subject with country, organisation and common name, an authority key identifier, valid now; for mdoc the document signer extended key usage `1.0.18013.5.1.2`)',
  'signer-not-access': '`signer-not-access` (the signer certificate and its key differ from the access certificate and its key)',
  'selective-disclosure': '`selective-disclosure` (`_sd_alg` is `sha-256`; no PID claim in the clear; every member of a disclosed object and every element of a disclosed array is a disclosure of its own)',
  'salt-entropy': '`salt-entropy` (every disclosure salt, or mdoc `random`, has at least 128 bits, and none repeats within the credential)',
  'algorithm-advertised': "`algorithm-advertised` (the credential's signature algorithm is in the configuration's `credential_signing_alg_values_supported`)",
  'unique-salts': '`unique-salts` (no salt or `random` value occurs in two credentials)',
  'unique-digests': '`unique-digests` (no disclosure or value digest occurs in two credentials)',
  'unique-status-index': '`unique-status-index` (no status list entry, `uri` and `idx`, occurs in two credentials)',
  'unique-device-key': '`unique-device-key` (no device key, `cnf.jwk` or `deviceKeyInfo`, occurs in two credentials)',
  'unique-signature': '`unique-signature` (no signature value occurs in two credentials)',
  'status-index-order': '`status-index-order` (per status list, the indices in issuance order are neither strictly monotonic over five or more credentials nor four in a row in arithmetic progression)',
  'batch-timestamps': '`batch-timestamps` (the credentials of batches received in one window of the declared precision (ICS-16) carry the same `iat`, `nbf`, `exp`, or MSO `signed`, `validFrom`, `validUntil`, at that precision)',
  'batch-spread': '`batch-spread` (no two credentials of one batch are on adjacent indices of a status list)',
  'no-wallet-identifier': "`no-wallet-identifier` (the decoded credential contains none of the WIA's `sub`, `jti`, `cnf` key coordinates and status `uri`, nor the KA's `jti` and status `uri`)",
  'anchor-issuance': '`anchor-issuance` (`issuer-trust`: the credential chains to the issuance anchor of `PP-T` on `TL-PID`)',
  'anchor-revocation': '`anchor-revocation` (`status-list-trust`: its Status List Token chains to the revocation anchor of `PP-T`, or to its issuance anchor where `TL-PID` lists it under both services)',
  'anchor-access': '`anchor-access` (the signed Credential Issuer metadata carries the access certificate the Test Registrar issued from `AC-A`, chaining to the `AC-A` anchor on `TL-AC`, and its signature verifies)',
  'outbound-privacy': '`outbound-privacy` (every request the Provider sent to `TL-WP` or the Test Status Provider during the test case is a GET of a published URL without query or fragment, body, cookie or `Authorization`)',
};

/** `CONF` of an `inspect` step: the named checks pass. */
export function inspected(checks: IssuerInspectionCheck[], what: string): IssuerExpectation {
  return { codes: ['CONF'], checks, text: `${what} The named checks pass: ${checks.map((c) => INSPECTION_CHECK_TEXT[c]).join('; ')}.` };
}

/** An `inspect` step over what earlier steps captured. */
export const inspectStep = (ofSteps: number[], text: string, expect: IssuerExpectation): IssuerStepDefinition => ({ text, run: { kind: 'inspect', ofSteps }, expect });

/** Valid `SCN-I` of a Wallet Unit in the pre-authorized code flow, `ISS`. */
export function unitIssuance(format: FormatVariant, unit: WalletUnit = 'CW-1', options: Partial<Omit<IssuanceAction, 'kind' | 'grant'>> & { why?: string; grant?: GrantVariant } = {}): IssuerStepDefinition {
  const { why, grant = 'PA', ...action } = options;
  const batch = action.batchSize && action.batchSize > 1 ? `, with ${action.batchSize} proofs over the keys of one KA (a batch of one logical PID)` : '';
  return {
    text: `The adapter creates a credential offer for \`${action.subject ?? 'SUBJ-1'}\` and the PID configuration in ${FORMAT_NAMES[format]} format, ${grant === 'PA' ? 'pre-authorized code' : GRANT_NAMES[grant]}. \`${unit}\` runs \`SCN-I\` without mutation${batch}${why ? ` (${why})` : ''}.`,
    run: issuance(format, grant, { walletUnit: unit, ...action }),
    expect: iss(format),
  };
}

/** A `trust-list` step: the Test Trust Infrastructure publishes a version of `TL-WP`, the Provider refreshes. */
export function trustListStep(change: string, action: Omit<IssuerTrustListAction, 'kind' | 'list'> = {}): IssuerStepDefinition {
  const [fault] = action.faults ?? [];
  return {
    text: `The Test Trust Infrastructure publishes a new version of \`TL-WP\` under a higher \`LoTESequenceNumber\`${fault ? '' : ', sealed by its scheme operator'}: ${change}${fault ? `; ${faultInfo(fault).text}` : ''}. The adapter makes the Provider read \`TL-WP\` again (\`refreshTrust\`), or the harness waits \`T_refresh\` (ICS-15).`,
    run: { kind: 'trust-list', list: 'TL-WP', ...action },
    expect: { codes: ['INFO'], text: 'The version, its sequence number and the refresh are recorded.' },
  };
}

/** `OBS-SL` of the credentials of `ofSteps` for `t` after the latest event: `REVOKED(t)`. */
export function revokedWithin(ofSteps: number[], t: 'T_rev' | 'T_chain', after: string): IssuerStepDefinition {
  const which = ofSteps.length > 1 ? `every credential of steps ${ofSteps.join(', ')}` : `the credential of step ${ofSteps[0]}`;
  return {
    text: `The harness polls the status list of ${which} anonymously every \`min(${t} / 20, 30 s)\` until \`${t}\` (${t === 'T_rev' ? 'ICS-06' : 'ICS-07'}) after ${after}, keeping every version with its \`iat\`, \`exp\` and the credential's status.`,
    run: { kind: 'observe-status', ofSteps, t },
    expect: {
      codes: [`REVOKED(${t})`],
      text: `No later than \`${t}\` after ${after}, a version of the list shows ${ofSteps.length > 1 ? 'each entry' : "the credential's entry"} as \`0x01\` (INVALID), and every later version polled shows it as \`0x01\` too.`,
    },
  };
}

/** `OBS-SL` of the credentials of `ofSteps` for `t`: `UNCHANGED`. */
export function unchangedFor(ofSteps: number[], t: string, during: string): IssuerStepDefinition {
  return {
    text: `The harness polls the status list of the credential${ofSteps.length > 1 ? 's' : ''} of step${ofSteps.length > 1 ? 's' : ''} ${ofSteps.join(', ')} anonymously ${during}, keeping every version.`,
    run: { kind: 'observe-status', ofSteps, t },
    expect: { codes: ['UNCHANGED'], text: `Every version polled shows the entr${ofSteps.length > 1 ? 'ies' : 'y'} as \`0x00\` (VALID).` },
  };
}
