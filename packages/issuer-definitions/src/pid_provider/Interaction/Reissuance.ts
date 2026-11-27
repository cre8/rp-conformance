// PP_WS_IA_Reissuance (`P-REISS`, issuer catalogue section 5.1.2): the refresh grant with the refresh token of the
// first issuance and the original DPoP key, then a credential request with the new access token.
import { defineIssuerTestCase, type FormatVariant, type GrantVariant, relevancy } from '@eudi-pcaf/core';
import { iss, issuance, preconditions, rej, technologyOf } from '../../wording';
import { both, conf, FORMAT, GRANT, MAIN, profileOf, ufPreconditions } from '../session';

const FIRST = '`CW-1` runs `SCN-I` for `SUBJ-1` without mutation; the token response carries a refresh token.';
const REFRESH =
  '`CW-1` sends a token request with `grant_type` `refresh_token` and the refresh token of step 1, its WIA and a fresh PoP, and a DPoP proof of its original DPoP key; then a nonce request and a credential request with the new access token and a key proof of a fresh attested key.';
const first = (format: FormatVariant, grant: GrantVariant) => ({ text: FIRST, run: issuance(format, grant), expect: iss(format) });

const reissuance001 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_Reissuance_001',
    variants: [format, grant],
    objective: 'Verify that the PID Provider issues a refresh token, DPoP-bound to the key of the Wallet Unit, that gives a new access token and a new credential without User interaction.',
    references: ['[ARF] Annex 2, ISSU_42, ISSU_63, ISSU_65', '[OpenID4VCI] section 14.5', '[HAIP] section 4.4', '[RFC 9449] section 5'],
    profile: profileOf(format, grant, 'P-REISS'),
    relevancy: relevancy.specificRequired,
    technology: technologyOf(format),
    preconditions: preconditions.base,
    steps: [first(format, grant), { text: REFRESH, run: { kind: 'token-reuse', artifact: 'refresh-token', ofStep: 1 }, expect: iss(format) }],
  });

const reissuance002 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_Reissuance_002_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that the PID Provider rejects a refresh token presented by another Wallet Unit than the one it was issued to.',
    references: ['[ARF] Annex 2, ISSU_65', '[RFC 6749] sections 6 and 10.4', '[RFC 9449] section 5'],
    profile: profileOf(format, grant, 'P-REISS'),
    relevancy: relevancy.specificRequired,
    technology: technologyOf(format),
    preconditions: ufPreconditions(),
    steps: [
      first(format, grant),
      {
        text: '`CW-2` sends a token request with `grant_type` `refresh_token` and the refresh token `CW-1` received in step 1, with its own client authentication: its `client_id`, its WIA and a fresh PoP, and a DPoP proof of a DPoP key of its own.',
        run: { kind: 'token-reuse', artifact: 'refresh-token', ofStep: 1, walletUnit: 'CW-2' },
        expect: rej(),
      },
    ],
    comments: [
      'The Wallet Unit authenticates with its WIA (a confidential client), so RFC 9449 section 5 does not bind its refresh token to the DPoP key: "Refresh tokens issued to confidential clients ... are not bound to the DPoP proof public key", they are bound to the client (RFC 6749 sections 6 and 10.4). The test therefore presents the refresh token as another client, `CW-2`, as the catalogue words the stimulus; a refresh with the same client and a new DPoP key is not a fault (spec review 2026-11-20, issuer catalogue section 8.3).',
    ],
  });

const reissuance003 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_Reissuance_003',
    variants: [format, grant],
    objective: 'Verify that a re-issued credential has the same attributes, new unique elements (salts, status index, key) and a new validity period.',
    references: ['[ARF] Annex 2, ISSU_35, ISSU_59, ISSU_63'],
    profile: profileOf(format, grant, 'P-REISS'),
    relevancy: relevancy.specificRequired,
    technology: technologyOf(format),
    preconditions: preconditions.base,
    steps: [
      first(format, grant),
      {
        text: REFRESH,
        run: { kind: 'token-reuse', artifact: 'refresh-token', ofStep: 1 },
        expect: both(
          iss(format),
          conf(
            ['reissue-same-claims', 'reissue-new-salts', 'reissue-new-status-index', 'reissue-new-key', 'reissue-new-validity'],
            'Compared with the credential of step 1, the new credential states the same claims about `SUBJ-1`, shares no disclosure salt, has another status list index, is bound to the new key, and has a later `iat` and `exp`; equal ones pass only when both fall within the timestamp precision the Provider declares (ICS-16).',
          ),
        ),
      },
    ],
  });

const reissuance004 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_Reissuance_004_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Record whether, after the PID was revoked, the refresh token still gives a credential.',
    references: ['[ARF] Annex 2, VCR_04, ISSU_65'],
    profile: profileOf(format, grant, 'P-REISS', 'P-HOOK'),
    relevancy: relevancy.specificOptional,
    technology: technologyOf(format),
    preconditions: ufPreconditions(),
    steps: [
      first(format, grant),
      { text: 'The adapter revokes the credential of step 1 (`setStatus` revoked).', run: { kind: 'issuer-event', event: 'set-status', status: 'revoked', ofStep: 1 }, expect: { codes: ['INFO'], text: 'The adapter reports the revocation.' } },
      {
        text: REFRESH,
        run: { kind: 'token-reuse', artifact: 'refresh-token', ofStep: 1 },
        expect: {
          codes: ['INFO'],
          text: 'Whether the Provider refuses the refresh or issues a new credential is recorded; HTTP 5xx fails. VCR_04 forbids reversing a revocation of the PID; whether a revoked PID may be replaced through its refresh token is not specified.',
        },
      },
    ],
    comments: [
      'Informational since the spec review of 2026-11-20 (issuer catalogue section 8.3): VCR_04 ("SHALL NOT reverse the revocation") does not cover a new credential obtained with the refresh token, and ISSU_65 is about the Wallet Unit, not the revoked PID. Refusing the refresh after a revocation is a design choice of the Provider; a later catalogue may make it a `POLICY` with an ICS item.',
    ],
  });

const reissuance005 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_Reissuance_005_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that a WIA presented at re-issuance is validated as at first issuance: a revoked Wallet Instance gets no new credential.',
    references: ['[ARF] Annex 2, ISSU_21, WUA_25'],
    profile: profileOf(format, grant, 'P-REISS'),
    relevancy: relevancy.specificRequired,
    technology: technologyOf(format),
    preconditions: ufPreconditions(),
    steps: [
      first(format, grant),
      { text: 'The Test Wallet Provider revokes the Wallet Instance of `CW-1` in `SL-WP-A`.', run: { kind: 'wallet-event', event: 'revoke-instance', walletUnit: 'CW-1' }, expect: { codes: ['INFO'], text: 'The Test Status Provider serves the new version of `SL-WP-A`.' } },
      { text: REFRESH, run: { kind: 'token-reuse', artifact: 'refresh-token', ofStep: 1 }, expect: rej() },
    ],
  });

export const definitions = [reissuance001, reissuance002, reissuance003, reissuance004, reissuance005].map((d) => d(FORMAT, GRANT));
