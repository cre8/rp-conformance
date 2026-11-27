// Building blocks of the test cases PP_WS_SM_ClientAttestation, _KeyAttestation and _ProofOfPossession (issuer
// catalogue section 5.1.3): a negative step names one issuer request fault of `ISSUER_FAULTS` and takes its FCAF
// wording from it; the status list steps reuse the RP harness's Status List Token faults on `SL-WP-A`.
import {
  defineIssuerTestCase,
  type FaultId,
  type FormatVariant,
  faultInfo,
  type GrantVariant,
  type IssuanceAction,
  type IssuerExpectation,
  type IssuerFaultId,
  type IssuerStepDefinition,
  type IssuerTestCaseDefinition,
  issuerFaultInfo,
  type Relevancy,
  type WalletUnit,
} from '@eudi-pcaf/core';
import { FORMAT_NAMES, GRANT_NAMES, iss, issuance, pidProfile, preconditions, technologyOf } from '../../wording';

export const CONTROL = 'PP_WS_IA_MainInteraction_001';

/** Preconditions of a `_UF` test case of these areas: the base, and the positive control in the same variant. */
export const ufPreconditions = [...preconditions.base, preconditions.control(CONTROL)];

type Fixed = 'variants' | 'profile' | 'technology' | 'preconditions' | 'control' | 'relevancy';

/**
 * A test case of these areas in a variant: the PID profile of the variant (plus `profile`), the base preconditions,
 * and for a `_UF` test case the positive control `PP_WS_IA_MainInteraction_001`.
 */
export const securityTestCase =
  (defaults: { relevancy: Relevancy; technology?: string[] }) =>
  (
    format: FormatVariant,
    grant: GrantVariant,
    definition: Omit<IssuerTestCaseDefinition, Fixed> & { relevancy?: Relevancy; profile?: IssuerTestCaseDefinition['profile'] },
  ) => {
    const uf = definition.id.endsWith('_UF');
    return defineIssuerTestCase({
      ...definition,
      variants: [format, grant],
      profile: definition.profile ?? pidProfile(format, grant),
      relevancy: definition.relevancy ?? defaults.relevancy,
      technology: [...technologyOf(format), ...(defaults.technology ?? [])],
      preconditions: uf ? ufPreconditions : preconditions.base,
      ...(uf ? { control: CONTROL } : {}),
    });
  };

/** `SCN-I` as the steps of these areas word it. */
const scnI = (format: FormatVariant, grant: GrantVariant, unit: WalletUnit = 'CW-1') =>
  `The adapter creates a credential offer for \`SUBJ-1\` and the PID configuration in ${FORMAT_NAMES[format]} format (${GRANT_NAMES[grant]}). \`${unit}\` runs \`SCN-I\`: token request with WIA, PoP and DPoP proof, nonce request, credential request with an \`openid4vci-proof+jwt\` that carries the KA in its \`key_attestation\` header`;

/** An issuance step of `CW-1` (or the unit of the action) whose messages are as `tail` says. */
export function issuanceStep(format: FormatVariant, grant: GrantVariant, tail: string, expect: IssuerExpectation, action: Partial<IssuanceAction> = {}): IssuerStepDefinition {
  return { text: `${scnI(format, grant, action.walletUnit)}, ${tail}.`, run: issuance(format, grant, action), expect };
}

/** A valid issuance step expecting `ISS`. */
export function validStep(format: FormatVariant, grant: GrantVariant, options: { unit?: WalletUnit; why?: string; action?: Partial<IssuanceAction> } = {}): IssuerStepDefinition {
  return {
    text: `${scnI(format, grant, options.unit)}, all valid${options.why ? ` (${options.why})` : ''}.`,
    run: issuance(format, grant, { ...(options.unit ? { walletUnit: options.unit } : {}), ...options.action }),
    expect: iss(format),
  };
}

/** `REJ` or `REJ:<code>` with the wording of section 2.5. */
export function rejected(code?: string | string[]): IssuerExpectation {
  const codes = Array.isArray(code) ? code : code ? [code] : [];
  if (codes.length <= 1) {
    return {
      codes: [codes[0] ? `REJ:${codes[0]}` : 'REJ'],
      text: `The Provider issues no credential and no token for the request and answers with HTTP 4xx and an OAuth or OpenID4VCI error object${codes[0] ? ` with \`error\` \`${codes[0]}\`` : ''}; never HTTP 5xx.`,
    };
  }
  return {
    codes: codes.map((c) => `REJ:${c}` as const),
    oneOf: true,
    text: `The Provider issues no credential for the request and answers with HTTP 4xx and an OAuth or OpenID4VCI error object with \`error\` ${codes.map((c) => `\`${c}\``).join(' or ')}; never HTTP 5xx.`,
  };
}

/**
 * A step that applies one issuer request fault. A fault whose target is no check (the request stays valid) is worded
 * as a property of the valid request.
 */
export function faultStep(format: FormatVariant, grant: GrantVariant, fault: IssuerFaultId, expect: IssuerExpectation, action: Partial<IssuanceAction> = {}): IssuerStepDefinition {
  const info = issuerFaultInfo(fault);
  return issuanceStep(format, grant, `${info.target ? 'all valid except that' : 'all valid, and'} ${info.text}`, expect, { ...action, faults: [fault] });
}

/** The `maintenance-period` check (ISSU_12c) of an issued credential, as `CONF`. */
export function maintenanceConf(format: FormatVariant, of: 'WIA' | 'KA'): IssuerExpectation {
  const claim = of === 'WIA' ? '`client_status`' : '`key_storage_status`';
  return {
    codes: ['CONF'],
    checks: ['maintenance-period'],
    text: `The Provider issues the PID in ${FORMAT_NAMES[format]} format, it passes every check of \`ISS\`, and its \`exp\` is no later than the \`exp\` of the ${claim} claim of the ${of} it was issued for (\`maintenance-period\`).`,
  };
}

/** `INFO` on a `wallet-event` step: what the Test Wallet Provider served is recorded. */
const recorded: IssuerExpectation = { codes: ['INFO'], text: 'The Test Wallet Provider serves the list; recorded in the report.' };

const SERVED_AT =
  'under a URL of this test case, to which the status reference of the following issuance points with the same index (a Provider may reuse a fetched `SL-WP-A` for its `ttl`)';

/** The Test Wallet Provider revokes the Wallet Instance (`wia`) or the WSCD (`ka`) of `CW-1` in `SL-WP-A`. */
export function revocationStep(of: 'wia' | 'ka'): IssuerStepDefinition {
  const what = of === 'wia' ? 'Wallet Instance of `CW-1`: the entry of its WIA' : 'WSCD of `CW-1`: the entry of its KA';
  return {
    text: `The Test Wallet Provider revokes the ${what} in \`SL-WP-A\` is set to 1 (revoked), in a new version of the list signed under the revocation anchor of \`WP-A\` and served ${SERVED_AT}.`,
    run: { kind: 'wallet-event', event: of === 'wia' ? 'revoke-instance' : 'revoke-wscd', walletUnit: 'CW-1' },
    expect: recorded,
  };
}

/**
 * The Status List Token faults of the RP harness (`RP_PP_SM_Revocation`, format JWT) that make `SL-WP-A` unusable for
 * a Provider. `status-list.signer-wp-a-revocation` is left out: `WP-A`'s revocation signer is the valid signer of
 * `SL-WP-A`.
 */
export const STATUS_LIST_FAULTS: FaultId[] = [
  'status-list.signature-bitflip',
  'status-list.alg-none',
  'status-list.bare-list',
  'status-list.exp-past',
  'status-list.sub-other',
  'status-list.typ-jwt',
  'status-list.no-sub',
  'status-list.no-iat',
  'status-list.no-status-list',
  'status-list.no-bits',
  'status-list.no-lst',
  'status-list.signer-ca-x',
  'status-list.no-x5c',
  'status-list.signer-self-signed',
  'status-list.signer-pp-b-revocation',
  'status-list.signer-ac-a',
  'status-list.signer-credential-certificate',
  'status-list.signer-other-issuance-certificate',
  'status-list.embedded-root',
  'status-list.signer-expired',
  'status-list.signer-not-yet-valid',
  'status-list.lst-not-base64url',
  'status-list.lst-not-zlib',
  'status-list.decompression-bomb',
  'status-list.bits-3',
  'status-list.es256k',
  'status-list.hs256-public-key',
];

/** HTTP behaviours of the Test Status Provider for the list's URL: the list cannot be obtained. */
export const STATUS_LIST_HTTP = [404, 500];

/**
 * One stimulus of `ClientAttestation_013_UF` / `KeyAttestation_009_UF`: the Test Wallet Provider serves `SL-WP-A` with
 * one Status List Token fault (or an HTTP error), then `CW-1` requests the PID and the Provider refuses.
 */
export function statusListSteps(format: FormatVariant, grant: GrantVariant, of: 'wia' | 'ka', stimulus: FaultId | number): IssuerStepDefinition[] {
  const attestation = of === 'wia' ? 'WIA' : 'KA';
  const changed =
    typeof stimulus === 'number'
      ? `answers the request for the list with HTTP ${stimulus} and no Status List Token`
      : `serves \`SL-WP-A\` as a Status List Token that is valid except that ${faultInfo(stimulus).text}`;
  return [
    {
      text: `The Test Wallet Provider ${changed}, ${SERVED_AT.replace('the status reference', `the status reference of the ${attestation}`)}. The entry of \`CW-1\`'s ${attestation} is 0 (valid).`,
      run: {
        kind: 'wallet-event',
        event: 'status-list',
        walletUnit: 'CW-1',
        statusList: { id: 'SL-WP-A', of, ...(typeof stimulus === 'number' ? { faults: [], httpStatus: stimulus } : { faults: [stimulus] }) },
      },
      expect: recorded,
    },
    issuanceStep(format, grant, `all valid; the status of its ${attestation} cannot be obtained from that list`, rejected()),
  ];
}
