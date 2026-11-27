// The grant faults of the points `authorization` and `token-request` (issuer harness design section 6.2), as pure
// functions over the parameters of a valid build: the PAR / authorization request parameters and the token request form.
// The faults that change the flow rather than a message (no PAR, waiting past a lifetime, ten wrong `tx_code` values
// first) are carried out by the issuance client (client.ts), which asks `grantFaultInfo` what a fault needs. Which
// check each fault must fail is in `GRANT_FAULTS` (packages/core/src/issuer/grant-faults.ts).
import { createHash, randomBytes, randomInt } from 'node:crypto';
import type { GrantFaultId } from '@eudi-pcaf/core';
import { base64url } from '@eudi-pcaf/forge';
import type { AuthorizationParameters } from './requests';

/** The `credential_configuration_id` and `scope` no Credential Issuer offers (`IA_AuthorizationCode_006_UF`). */
export const UNKNOWN_CONFIGURATION = 'unknown-configuration';
export const UNKNOWN_SCOPE = 'unknown-scope';
/** The `redirect_uri` of `token-request.redirect-uri-other`. */
export const OTHER_REDIRECT_URI = 'https://other-wallet.rp-conformance.invalid/callback';

/** A PKCE `code_verifier` (RFC 7636 section 4.1): 32 random octets, base64url, 43 characters. */
export const newCodeVerifier = () => base64url.encode(randomBytes(32));

/** The `S256` `code_challenge` of a verifier (RFC 7636 section 4.2). */
export const s256Challenge = (verifier: string) => base64url.encode(createHash('sha256').update(verifier).digest());

/** A `tx_code` of the same length and character class as `right`, different from it. */
export function wrongTxCode(right: string): string {
  const numeric = /^\d+$/.test(right);
  for (;;) {
    const candidate = numeric
      ? String(randomInt(0, 10 ** right.length)).padStart(right.length, '0')
      : base64url.encode(randomBytes(right.length)).slice(0, right.length);
    if (candidate !== right) return candidate;
  }
}

/** Applies a fault of the point `authorization` to the parameters of the (pushed) authorization request. */
export function applyAuthorizationFault(id: GrantFaultId | undefined, params: AuthorizationParameters, context: { codeVerifier: string }): AuthorizationParameters {
  switch (id) {
    case 'authorization.pkce-missing':
      return { ...params, code_challenge: undefined, code_challenge_method: undefined };
    case 'authorization.pkce-plain':
      return { ...params, code_challenge: context.codeVerifier, code_challenge_method: 'plain' };
    case 'authorization.authorization-details-unknown':
      return { ...params, authorization_details: JSON.stringify([{ type: 'openid_credential', credential_configuration_id: UNKNOWN_CONFIGURATION }]) };
    case 'authorization.scope-unknown':
      return { ...params, scope: params.scope ? `${params.scope} ${UNKNOWN_SCOPE}` : UNKNOWN_SCOPE };
    default:
      return params;
  }
}

/** The form of a token request: grant parameters by name, undefined for one left out. */
export type TokenForm = Record<string, string | undefined>;

export interface TokenFaultContext {
  /** The `pre-authorized_code` and `tx_code` of the second offer (`token-request.pre-authorized-code-other-offer`). */
  otherOffer?: { preAuthorizedCode: string; txCode?: string };
}

/** Applies a fault of the point `token-request` that changes one token request. */
export function applyTokenRequestFault(id: GrantFaultId | undefined, form: TokenForm, context: TokenFaultContext = {}): TokenForm {
  switch (id) {
    case 'token-request.code-verifier-wrong':
      return { ...form, code_verifier: newCodeVerifier() };
    case 'token-request.code-verifier-missing':
      return { ...form, code_verifier: undefined };
    case 'token-request.redirect-uri-other':
      return { ...form, redirect_uri: OTHER_REDIRECT_URI };
    case 'token-request.tx-code-wrong':
      return { ...form, tx_code: wrongTxCode(form.tx_code ?? '000000') };
    case 'token-request.tx-code-missing':
      return { ...form, tx_code: undefined };
    case 'token-request.pre-authorized-code-other-offer': {
      if (!context.otherOffer) throw new Error(`${id} needs the code of a second offer`);
      return { ...form, 'pre-authorized_code': context.otherOffer.preAuthorizedCode, tx_code: context.otherOffer.txCode };
    }
    default:
      return form;
  }
}
