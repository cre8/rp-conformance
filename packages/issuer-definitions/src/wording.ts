// Building blocks of the issuer definitions (issuer harness design section 6): how a definition names the credential
// configuration of a variant, the issuance step, and the wording the steps and expected results share.
import {
  FORMAT_VARIANTS,
  type FormatVariant,
  GRANT_VARIANTS,
  type GrantVariant,
  type IssuanceAction,
  type IssuerExpectation,
  issuerProfiles,
} from '@eudi-pcaf/core';

/**
 * The credential configuration of a step, by reference to the ICS: `ICS-02.<format variant>` names the configuration
 * that issues the PID (or the Provider's attestation) in that format, for example `ICS-02.SD: pid-sd-jwt-vc`. A
 * definition cannot name a configuration ID, since each Provider chooses its own; the controller resolves the reference
 * against the ICS before it asks the adapter for an offer.
 */
export const configurationOf = (format: FormatVariant) => `ICS-02.${format}`;

export const FORMAT_NAMES: Record<FormatVariant, string> = { SD: 'SD-JWT VC', MD: 'mdoc' };
export const GRANT_NAMES: Record<GrantVariant, string> = { PA: 'pre-authorized code flow', AC: 'authorization code flow with PAR and PKCE' };

/** The profile applicability of a PID Provider test case in a format and grant variant. */
export const pidProfile = (format: FormatVariant, grant: GrantVariant) => [issuerProfiles['P-PID'], issuerProfiles[`P-${format}`], issuerProfiles[`P-${grant}`]];

/** `Technology` of a variant. */
export const technologyOf = (format: FormatVariant) => ['OpenID4VCI', format === 'SD' ? 'SD-JWT VC' : 'ISO/IEC 18013-5 mdoc'];

/** `SCN-I` for a variant: `CW-1`, `SUBJ-1`, the PID configuration of the format, the grant; no fault unless given. */
export function issuance(format: FormatVariant, grant: GrantVariant, options: Partial<Omit<IssuanceAction, 'kind' | 'grant'>> = {}): IssuanceAction {
  return {
    kind: 'issuance',
    walletUnit: 'CW-1',
    subject: 'SUBJ-1',
    configurations: [configurationOf(format)],
    grant: GRANT_VARIANTS[grant],
    faults: [],
    ...options,
  };
}

/** The checks `ISS` runs on every issued credential (issuer harness design section 6.3), as the FCAF text names them. */
const ISS_CHECKS =
  'format, `issuer-trust` to `PP-T` on `TL-PID`, `issuer-signature`, `disclosures`, `validity`, `holder-binding` (bound to a proof key the KA attests) and `status-reference`, and the Status List Token it references passes the status list checks';

/** `ISS` (issuer catalogue section 2.5): the Provider issues, and every credential passes the reference validator. */
export function iss(format: FormatVariant): IssuerExpectation {
  return {
    codes: ['ISS'],
    text: `The Provider issues the credential (HTTP 200) in ${FORMAT_NAMES[format]} format (\`${FORMAT_VARIANTS[format]}\`). Every credential passes ${ISS_CHECKS}.`,
  };
}

/** `REJ` (issuer catalogue section 2.5): no credential and no token for the request, a 4xx with an error object. */
export function rej(code?: string): IssuerExpectation {
  return {
    codes: [code ? `REJ:${code}` : 'REJ'],
    text: `The Provider issues no credential and no token for the request and answers with HTTP 4xx and an OAuth or OpenID4VCI error object${code ? ` with \`error\` \`${code}\`` : ''}; never HTTP 5xx.`,
  };
}

export const preconditions = {
  /** Every issuer test case: enrolment and `default_configuration_PP_1` (issuer catalogue sections 3.3 to 3.5). */
  base: [
    'The Provider is enrolled by the Test Registrar (issuer catalogue section 3.3): its credential signer under `PP-T` on `TL-PID`, its status list signer under the revocation anchor of `PP-T`, its access and registration certificates.',
    'The Provider is configured as `default_configuration_PP_1` (section 3.5) and trusts `TL-WP` for Wallet Providers.',
    'Wallet Unit `CW-1` of `WP-A` (section 3.4): a valid WIA and a valid KA with `iso_18045_high`, neither revoked.',
    'The adapter can create an offer for `SUBJ-1` (ICS-17).',
  ],
  /** The positive control a `_UF` test case depends on, named so `defineIssuerTestCase` can check `control`. */
  control: (id: string) => `The positive control \`${id}\` passed in the same variant.`,
};
