// The grant checks of the reference validator (issuer harness design sections 6.2 and 7): what an Authorization Server
// must verify in the authorization code flow with PAR and PKCE and in the pre-authorized code flow before it issues a
// code or a token. A conforming Authorization Server accepts a flow only if every check passes, so each grant fault, and
// each reuse of an artifact by a `token-reuse` step, can be shown to fail exactly one of them (level 1, no issuer
// involved). The rules are written out here from RFC 6749, RFC 7636, RFC 9126 and OpenID4VCI 1.0, not imported from the
// issuance client, so a wrong rule in the client is not repeated by the validator.
import { createHash } from 'node:crypto';
import { AUTHORIZATION_RESPONSE_CHECKS, type CheckResult } from '@eudi-pcaf/core';
import { CheckRecorder, NotApplicable, type ValidationMode, type ValidationResult } from './checks';

/** Request parameters by name; undefined for one that was not sent. */
export type Parameters = Record<string, string | undefined>;

/** What the Conformance Wallet sent in one grant, and what the Authorization Server answered that the checks need. */
export interface GrantFlowInput {
  grant: 'authorization_code' | 'pre-authorized_code';
  /** The `client_id` the token request is authenticated for (the `sub` of the WIA it carries). */
  clientId: string;
  /** Authorization code flow: the parameters of the pushed authorization request; undefined when none was sent. */
  par?: Parameters;
  /** The `request_uri` and `expires_in` the PAR response returned. */
  requestUri?: string;
  expiresIn?: number;
  /** The query of the authorization request the wallet sent to the authorization endpoint. */
  authorizationRequest?: Parameters;
  /** Seconds between the PAR response and the authorization request. */
  secondsAfterPar?: number;
  /** The code of the authorization response. */
  issuedCode?: string;
  /** Pre-authorized code flow: the code and `tx_code` of the offer being redeemed. */
  offerCode?: string;
  offerTxCode?: string;
  /** Seconds between the offer and the token request. */
  secondsAfterOffer?: number;
  /** Token requests with a wrong `tx_code` for this code before this one. */
  wrongTxCodeAttempts?: number;
  /** The form of the token request; undefined when the flow ended before it. */
  tokenRequest?: Parameters;
}

export interface GrantFlowOptions {
  /** `credential_configurations_supported` of the Credential Issuer metadata, by ID. */
  configurations: Record<string, { scope?: string }>;
  /** `request_uri` values an authorization request already used. */
  usedRequestUris?: string[];
  /** Codes (authorization or pre-authorized) already redeemed at the token endpoint. */
  redeemedCodes?: string[];
  /** The lifetime of a pre-authorized code, seconds (ICS-14.pre_authorized_code). */
  preAuthorizedCodeLifetimeSeconds?: number;
  /**
   * Wrong `tx_code` values after which a code is locked. OpenID4VCI 1.0 sets no number (catalogue section 8.2); the
   * catalogue's stimulus is ten, so the default is ten: the right value after ten wrong ones must be refused.
   */
  txCodeAttemptLimit?: number;
  mode?: ValidationMode;
}

const S256 = (verifier: string) => createHash('sha256').update(verifier).digest('base64url');
const PKCE_VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/;
const fail = (message: string): never => {
  throw new Error(message);
};

/** The parameters an authorization request was made with: the pushed ones, else those of its query. */
const authorizationParameters = (input: GrantFlowInput): Parameters | undefined => input.par ?? input.authorizationRequest;

/** Checks one grant (`GRANT_CHECKS`); checks of the other grant are skipped. */
export async function validateGrantFlow(input: GrantFlowInput, options: GrantFlowOptions): Promise<ValidationResult> {
  const recorder = new CheckRecorder(options.mode ?? 'all');
  const code = input.grant === 'authorization_code';
  const onlyFor = (grant: GrantFlowInput['grant']) => (input.grant === grant ? undefined : new NotApplicable(`not a check of the ${input.grant} grant`));
  const token = input.tokenRequest;
  const noToken = () => new NotApplicable('the flow ended before the token request');

  return recorder.collect(async () => {
    // RFC 9126 section 4; HAIP section 4: the authorization request refers to a pushed request.
    await recorder.run('par', [], () => {
      const skip = onlyFor('authorization_code');
      if (skip) return skip;
      if (!input.par) fail('no pushed authorization request was sent');
      if (!input.authorizationRequest?.request_uri) fail('the authorization request carries no request_uri');
      const extra = Object.keys(input.authorizationRequest ?? {}).filter((name) => !['client_id', 'request_uri'].includes(name) && input.authorizationRequest?.[name] !== undefined);
      if (extra.length) fail(`the authorization request carries parameters outside the pushed request: ${extra.join(', ')}`);
      return 'pushed; the authorization request carries client_id and request_uri only';
    });
    // RFC 7636 section 4.3; HAIP section 4: PKCE with S256.
    await recorder.run('pkce', [], () => {
      const skip = onlyFor('authorization_code');
      if (skip) return skip;
      const params = authorizationParameters(input);
      if (!params?.code_challenge) fail('no code_challenge');
      if (params?.code_challenge_method !== 'S256') fail(`code_challenge_method ${params?.code_challenge_method ?? 'absent'}, not S256`);
      if (!/^[A-Za-z0-9_-]{43}$/.test(params?.code_challenge ?? '')) fail('code_challenge is not a base64url SHA-256 value');
      return 'S256';
    });
    // OpenID4VCI 1.0 sections 5.1.1 and 5.1.2: what is requested is offered.
    await recorder.run('authorization-details', [], () => {
      const skip = onlyFor('authorization_code');
      if (skip) return skip;
      const params = authorizationParameters(input) ?? {};
      const requested: string[] = [];
      if (params.authorization_details !== undefined) {
        let details: unknown;
        try {
          details = JSON.parse(params.authorization_details);
        } catch {
          fail('authorization_details is not JSON');
        }
        if (!Array.isArray(details) || details.length === 0) fail('authorization_details is not a non-empty array');
        for (const detail of details as Record<string, unknown>[]) {
          if (detail?.type !== 'openid_credential') fail(`authorization_details type ${String(detail?.type)}, not openid_credential`);
          const id = detail.credential_configuration_id;
          if (typeof id !== 'string' || !(id in options.configurations)) fail(`credential_configuration_id ${String(id)} is not offered`);
          requested.push(id as string);
        }
      }
      // Section 5.1.2: "Credential Issuers MUST ignore unknown scope values in a request"; only known ones request a
      // credential.
      if (params.scope !== undefined) {
        const scopes = new Set(Object.values(options.configurations).map((c) => c.scope).filter(Boolean));
        requested.push(...params.scope.split(' ').filter((s) => s && scopes.has(s)));
      }
      if (!requested.length) fail('neither authorization_details nor a known scope value');
      return requested.join(', ');
    });
    // RFC 9126 sections 2.2, 4 and 7.3: the request_uri the PAR returned, used once, before it expires.
    await recorder.run('request-uri', ['par'], () => {
      const uri = input.authorizationRequest?.request_uri;
      if (uri !== input.requestUri) fail(`request_uri ${String(uri)} is not the one the PAR response returned`);
      if (uri && options.usedRequestUris?.includes(uri)) fail('the request_uri was already used by an authorization request');
      if (input.expiresIn !== undefined && (input.secondsAfterPar ?? 0) > input.expiresIn) fail(`used ${input.secondsAfterPar} s after the PAR response, expires_in ${input.expiresIn}`);
      return 'returned by the PAR, unused, not expired';
    });
    // RFC 6749 section 4.1.3: the code issued, not redeemed before.
    await recorder.run('authorization-code', [], () => {
      if (!code) return onlyFor('authorization_code') as NotApplicable;
      if (!token) return noToken();
      if (!token.code || token.code !== input.issuedCode) fail('the code is not the one of the authorization response');
      if (options.redeemedCodes?.includes(token.code as string)) fail('the code was already redeemed');
      return 'issued, not redeemed before';
    });
    // RFC 6749 sections 4.1.3 and 10.5: the code is redeemed by the client it was issued to, for its redirect_uri.
    await recorder.run('code-binding', [], () => {
      if (!code) return onlyFor('authorization_code') as NotApplicable;
      if (!token) return noToken();
      const params = authorizationParameters(input) ?? {};
      if (input.clientId !== params.client_id) fail(`the token request is authenticated for client ${input.clientId}, the code was issued to ${String(params.client_id)}`);
      if (token.client_id !== undefined && token.client_id !== params.client_id) fail(`client_id ${token.client_id} differs from ${String(params.client_id)}`);
      if (token.redirect_uri !== params.redirect_uri) fail(`redirect_uri ${String(token.redirect_uri)} differs from ${String(params.redirect_uri)}`);
      return 'same client_id and redirect_uri';
    });
    // RFC 7636 section 4.6.
    await recorder.run('pkce-verifier', ['pkce'], () => {
      if (!token) return noToken();
      const verifier = token.code_verifier;
      if (!verifier) fail('no code_verifier');
      if (!PKCE_VERIFIER.test(verifier as string)) fail('code_verifier is not 43 to 128 unreserved characters');
      if (S256(verifier as string) !== authorizationParameters(input)?.code_challenge) fail('S256(code_verifier) differs from code_challenge');
      return 'S256(code_verifier) = code_challenge';
    });
    // OpenID4VCI 1.0 sections 4.1.1 and 6.3: the code of this offer, once, within its lifetime.
    await recorder.run('pre-authorized-code', [], () => {
      if (code) return onlyFor('pre-authorized_code') as NotApplicable;
      if (!token) return noToken();
      const presented = token['pre-authorized_code'];
      if (!presented || presented !== input.offerCode) fail('the pre-authorized_code is not the one of the offer being redeemed');
      if (options.redeemedCodes?.includes(presented as string)) fail('the pre-authorized_code was already redeemed');
      const lifetime = options.preAuthorizedCodeLifetimeSeconds;
      if (lifetime !== undefined && (input.secondsAfterOffer ?? 0) > lifetime) fail(`used ${input.secondsAfterOffer} s after the offer, lifetime ${lifetime} s`);
      return 'the offer’s code, once, within its lifetime';
    });
    // OpenID4VCI 1.0 sections 6.1 and 6.3: the tx_code of the offer, and no guessing.
    await recorder.run('tx-code', ['pre-authorized-code'], () => {
      if (!token) return noToken();
      if (input.offerTxCode === undefined) return new NotApplicable('the offer requires no tx_code');
      if (token.tx_code === undefined) fail('no tx_code');
      if (token.tx_code !== input.offerTxCode) fail('wrong tx_code');
      const limit = options.txCodeAttemptLimit ?? 10;
      if ((input.wrongTxCodeAttempts ?? 0) >= limit) fail(`${input.wrongTxCodeAttempts} wrong tx_code values were sent before, the limit is ${limit}`);
      return 'the offer’s tx_code';
    });
  });
}

/**
 * The `CONF` checks of an authorization response (RFC 6749 section 4.1.2, RFC 9207, HAIP section 4): a code, `state`
 * returned unaltered, `iss` the Authorization Server's issuer identifier.
 */
export function checkAuthorizationResponse(response: { code?: string; state?: string; iss?: string } | undefined, expected: { state: string; issuer: string }): CheckResult[] {
  if (!response) return AUTHORIZATION_RESPONSE_CHECKS.map((check) => ({ check, status: 'fail', detail: 'no authorization response' }));
  return [
    response.code ? { check: 'authorization-response-code', status: 'pass' } : { check: 'authorization-response-code', status: 'fail', detail: 'no code' },
    response.state === expected.state
      ? { check: 'authorization-response-state', status: 'pass', detail: 'unaltered' }
      : { check: 'authorization-response-state', status: 'fail', detail: `state ${String(response.state)}, sent ${expected.state}` },
    response.iss === expected.issuer
      ? { check: 'authorization-response-iss', status: 'pass', detail: response.iss }
      : { check: 'authorization-response-iss', status: 'fail', detail: `iss ${String(response.iss)}, the issuer is ${expected.issuer}` },
  ];
}
