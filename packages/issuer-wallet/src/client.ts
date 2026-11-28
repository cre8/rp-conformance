// The issuance client (issuer harness design section 5.1): the pre-authorized code flow and the authorization code
// flow with PAR, PKCE and `issuer_state` (the authorization request goes to the adapter's `authenticateSubject`), with
// the grant faults of the points `authorization` and `token-request` (grant-faults.ts): offer by value
// or by reference, Credential Issuer and Authorization Server metadata (`SCN-M`), token request with client attestation
// and DPoP, nonce, credential request with an `openid4vci-proof+jwt` carrying the KA (`SCN-I`), for SD-JWT VC and mdoc,
// and for several configurations with one access token. The libraries parse and
// validate offer and metadata; every message the client sends to the token, nonce and credential endpoints is built
// by a function of its own (`jwts.ts`, `requests.ts`) and passes the hooks before it is signed or sent.
import { createHash, randomBytes } from 'node:crypto';
import { type CallbackContext, setGlobalConfig } from '@openid4vc/oauth2';
import { EXPIRY_MARGIN_SECONDS, type GrantFaultId, TX_CODE_WRONG_ATTEMPTS } from '@eudi-pcaf/core';
import { type CredentialOfferObject, determineAuthorizationServerForCredentialOffer, type IssuerMetadataResult, Openid4vciClient } from '@openid4vc/openid4vci';
import { base64url, type EcKeyPair, generateEcKeyPair } from '@eudi-pcaf/forge';
import { type JwtParts, keySigner, signJwt, type TestWalletProvider, type WalletUnitId, wiaPopParts } from '@eudi-pcaf/wallet-provider';
import { type HttpExchange, type HttpRequestMessage, type HttpResponseRecord, type IssuanceStep, jsonOf, oauthErrorOf, recordingFetch, type RequestHook, send } from './http';
import { dpopProofParts, keyProofParts } from './jwts';
import { applyAuthorizationFault, applyTokenRequestFault, newCodeVerifier, s256Challenge, type TokenForm, wrongTxCode } from './grant-faults';
import {
  AUTHORIZATION_CODE_GRANT,
  type AuthorizationParameters,
  authorizationCodeTokenRequest,
  authorizationRequestUrl,
  credentialRequest,
  nonceRequest,
  PRE_AUTHORIZED_CODE_GRANT,
  parRequest,
  signedMetadataRequest,
  tokenRequest,
} from './requests';

/** The JWTs the client signs, by fault point (issuer harness design section 6.2). */
export type JwtPoint = 'wia-pop' | 'dpop' | 'proof';

/** Changes header and payload of a JWT after its valid build and before it is signed. */
export type JwtHook = (point: JwtPoint, parts: JwtParts, context: { step: IssuanceStep }) => JwtParts | Promise<JwtParts>;

/** The seams of the fault layer (issue 18): a hook may return its input unchanged, a changed copy, or a replacement. */
export interface MessageHooks {
  jwt?: JwtHook;
  request?: RequestHook;
}

/** A KA and the private keys of its `attested_keys`, in the same order. */
export interface KeyAttestationWithKeys {
  jwt: string;
  keys: EcKeyPair[];
}

/** What the client needs of a Wallet Unit: its `client_id`, the WIA's `cnf` key, and fresh WIAs and KAs. */
export interface WalletUnitBinding {
  id: string;
  clientId: string;
  /** The WIA's `cnf` key, which signs the PoP. */
  instanceKey: EcKeyPair;
  wia(): Promise<string>;
  keyAttestation(): Promise<KeyAttestationWithKeys>;
}

/** A Wallet Unit of the Test Wallet Provider: a fresh WIA and a fresh KA (with fresh attested keys) per issuance. */
export function walletUnitOf(twp: TestWalletProvider, id: WalletUnitId): WalletUnitBinding {
  const unit = twp.units[id];
  return {
    id,
    clientId: unit.clientId,
    instanceKey: unit.instanceKey,
    wia: () => twp.wia(id),
    keyAttestation: () => twp.keyAttestation(id),
  };
}

/** The offer as the client received it and as it resolved. */
export interface OfferEvidence {
  /** What the client was given: a `openid-credential-offer://` URI or a bare `credential_offer_uri`. */
  input: string;
  byReference: boolean;
  credentialOfferUri?: string;
  offer: CredentialOfferObject;
}

export interface MetadataEvidence {
  result: IssuerMetadataResult;
  /** The answer to `Accept: application/jwt` at the Credential Issuer metadata URL. */
  signed?: HttpResponseRecord;
}

export interface TokenResult {
  accessToken: string;
  tokenType: string;
  response: Record<string, unknown>;
}

/** A credential as received, with the proof key it is bound to and the KA that attests that key. */
export interface IssuedCredential {
  credentialConfigurationId: string;
  format: string;
  credential: string;
  proofKey: EcKeyPair;
  keyAttestation: string;
}

/** The authorization response: the query of the redirect to the wallet's `redirect_uri` (RFC 6749 section 4.1.2). */
export interface AuthorizationResponse {
  location: string;
  code?: string;
  state?: string;
  iss?: string;
  error?: string;
  errorDescription?: string;
}

/** The authorization part of the authorization code flow: PAR, the authorization request and its response. */
export interface AuthorizationEvidence {
  /** The issuer identifier of the Authorization Server. */
  authorizationServer: string;
  /** The parameters of the (pushed) authorization request, as sent. */
  parameters: AuthorizationParameters;
  /** Whether they were pushed (RFC 9126); false for `authorization.no-par`. */
  pushed: boolean;
  codeVerifier: string;
  redirectUri: string;
  state: string;
  /** The PAR response: `request_uri`, `expires_in`, and when it arrived. */
  requestUri?: string;
  expiresIn?: number;
  parAt?: string;
  /** The authorization request URL handed to the adapter's `authenticateSubject`, and when. */
  url?: string;
  sentAt?: string;
  /** Seconds the client waited between PAR and the authorization request (`authorization.request-uri-expired`). */
  waitedSeconds?: number;
  response?: AuthorizationResponse;
}

/** The grant the client ran, with what it needs to repeat a request of it (`token-reuse`). */
export interface GrantEvidence {
  grant: 'pre-authorized_code' | 'authorization_code';
  clientId: string;
  /** The issuer identifier of the Authorization Server. */
  authorizationServer?: string;
  /** Pre-authorized code flow: the code and `tx_code` of the offer. */
  preAuthorizedCode?: string;
  txCode?: string;
  /** When the offer was resolved, and seconds waited before the token request (`token-request.pre-authorized-code-expired`). */
  offerResolvedAt?: string;
  waitedSeconds?: number;
  /** Token requests sent with a wrong `tx_code` before the last one (`token-request.tx-code-repeated`). */
  wrongTxCodeAttempts?: number;
  /** Authorization code flow. */
  authorization?: AuthorizationEvidence;
  /** The form of the last token request, as sent. */
  tokenRequest?: TokenForm;
  /** The fault of the points `authorization` and `token-request` the client applied. */
  fault?: GrantFaultId;
}

/** A fault waits longer than the run allows (`IssueOptions.maxWaitSeconds`); the step cannot be executed in this run. */
export class WaitLimitExceeded extends Error {
  constructor(
    readonly waitsFor: 'request-uri' | 'pre-authorized-code',
    readonly seconds: number,
    readonly limit: number,
  ) {
    super(`the ${waitsFor === 'request-uri' ? 'PAR request_uri' : 'pre-authorized code'} expires in ${seconds - EXPIRY_MARGIN_SECONDS} s; waiting ${seconds} s (one hour after it) exceeds the run's limit of ${limit} s`);
  }
}

/** Everything one run of `SCN-I` saw and sent. */
export interface IssuanceEvidence {
  walletUnit: string;
  exchanges: HttpExchange[];
  offer?: OfferEvidence;
  metadata?: MetadataEvidence;
  authorizationServer?: string;
  grant?: GrantEvidence;
  /** Set when a fault would have waited longer than the run allows. */
  waitExceeded?: { waitsFor: 'request-uri' | 'pre-authorized-code'; seconds: number; limit: number };
  token?: TokenResult;
  cNonce?: string;
  credentials: IssuedCredential[];
  /** Set when the flow stopped before a credential arrived. */
  error?: string;
}

export interface IssuanceClientOptions {
  /** Accept `http` URLs (local runs against EUDIPLO). */
  allowInsecureUrls?: boolean;
  hooks?: MessageHooks;
}

export interface IssueOptions {
  /** The offer: `openid-credential-offer://?credential_offer=…` (by value) or `…?credential_offer_uri=…` (by reference). */
  offer: string;
  txCode?: string;
  /** Default the first of the offer's `credential_configuration_ids`. */
  credentialConfigurationId?: string;
  /**
   * Several configurations of the offer, requested one after the other with the same access token, each with a fresh
   * `c_nonce` and proof (`IA_MainInteraction_003`: both formats of the PID with one access token). Takes precedence
   * over `credentialConfigurationId`.
   */
  credentialConfigurationIds?: string[];
  /** Also fetch the metadata with `Accept: application/jwt` (default true). */
  signedMetadata?: boolean;
  /** The grant to run; default the pre-authorized code grant when the offer has one, else the authorization code grant. */
  grant?: 'pre-authorized_code' | 'authorization_code';
  /** Authorization code flow: the adapter's `authenticateSubject` for the subject of the offer. */
  authenticate?: Authenticate;
  /** Authorization code flow: stop after the authorization response, before the token request. */
  stopAfterAuthorization?: boolean;
  /** A fault of the points `authorization` or `token-request` (at most one per issuance). */
  grantFault?: GrantFaultId;
  /** `token-request.pre-authorized-code-other-offer`: a second offer of the SUT, by value or by reference. */
  otherOffer?: { offer: string; txCode?: string };
  /** The lifetime of a pre-authorized code the SUT declares (ICS-14.pre_authorized_code), seconds. */
  preAuthorizedCodeLifetimeSeconds?: number;
  /** Request each credential by the `credential_identifier` the token response issued for it (issue 20, `MS_CredentialEndpoint_002`). */
  credentialIdentifier?: boolean;
  /** The longest a fault may wait, seconds (default 0: a fault that waits is not executed). */
  maxWaitSeconds?: number;
  /** How the client waits; default a timer. */
  sleep?: (ms: number) => Promise<void>;
  /**
   * Issue 27: whether the credential request carries a key proof with its KA. `auto` (default): where the configuration
   * lists `proof_types_supported` (OpenID4VCI 1.0 section 8.2); `always`: also where it lists none; `never`: none, as for
   * a configuration the Provider declares not device-bound (`AP_WS_SM_KeyAttestation_102`).
   */
  proof?: 'auto' | 'always' | 'never';
}

/** The adapter's `authenticateSubject`: the authorization request URL in, the redirect to the wallet out. */
export type Authenticate = (authorizationRequestUrl: string) => Promise<string>;

/** The first `credential_identifier` the token response's `authorization_details` issued for a configuration. */
export function credentialIdentifierOf(token: TokenResult, configurationId: string): string {
  const details = Array.isArray(token.response.authorization_details) ? (token.response.authorization_details as Record<string, unknown>[]) : [];
  const identifiers = details.filter((d) => d.credential_configuration_id === configurationId).flatMap((d) => (Array.isArray(d.credential_identifiers) ? d.credential_identifiers : []));
  const [identifier] = identifiers.filter((i): i is string => typeof i === 'string');
  if (!identifier) throw new IssuanceError(`the token response issued no credential_identifiers for ${configurationId}`);
  return identifier;
}

/** The `redirect_uri` of the Conformance Wallet. It is never fetched: the client reads the redirect's query. */
export const WALLET_REDIRECT_URI = 'https://wallet.rp-conformance.invalid/callback';

const OFFER_SCHEME = 'openid-credential-offer://';

const hash: CallbackContext['hash'] = (data, alg) => createHash(alg.replace('-', '').toLowerCase()).update(data).digest();

const notUsed = () => {
  throw new Error('not used by the issuance client');
};

/** An error of the flow, with the exchange that caused it. */
export class IssuanceError extends Error {
  constructor(
    message: string,
    readonly exchange?: HttpExchange,
  ) {
    super(message);
  }
}

/** The URL of the Credential Issuer metadata (OpenID4VCI 1.0 section 12.2.2): well-known segment before the path. */
export function credentialIssuerMetadataUrl(credentialIssuer: string): string {
  const url = new URL(credentialIssuer);
  const path = url.pathname === '/' ? '' : url.pathname.replace(/\/$/, '');
  return `${url.origin}/.well-known/openid-credential-issuer${path}`;
}

/**
 * The client of one Wallet Unit. It holds the unit's DPoP key for all its issuances (design section 5.1: one DPoP key
 * per Wallet Unit) and the last `DPoP-Nonce` of each server.
 */
export class IssuanceClient {
  private readonly dpopNonces = new Map<string, string>();

  private constructor(
    readonly unit: WalletUnitBinding,
    readonly dpopKey: EcKeyPair,
    private readonly options: IssuanceClientOptions,
  ) {}

  static async create(unit: WalletUnitBinding, options: IssuanceClientOptions = {}): Promise<IssuanceClient> {
    if (options.allowInsecureUrls) setGlobalConfig({ allowInsecureUrls: true });
    return new IssuanceClient(unit, await generateEcKeyPair(), options);
  }

  /** Runs `SCN-I` without mutation: offer, metadata, token, nonce, credential. Never throws; errors land in the evidence. */
  async issue(options: IssueOptions): Promise<IssuanceEvidence> {
    const evidence: IssuanceEvidence = { walletUnit: this.unit.id, exchanges: [], credentials: [] };
    try {
      const offer = await this.resolveOffer(options.offer, evidence);
      const metadata = await this.fetchMetadata(offer.offer.credential_issuer, evidence, { signed: options.signedMetadata ?? true });
      const configurationId = options.credentialConfigurationIds?.[0] ?? options.credentialConfigurationId ?? offer.offer.credential_configuration_ids[0];
      const grant = options.grant ?? (offer.offer.grants?.[PRE_AUTHORIZED_CODE_GRANT] ? 'pre-authorized_code' : 'authorization_code');
      let token: TokenResult;
      if (grant === 'authorization_code') {
        if (!options.authenticate) throw new IssuanceError('the authorization code flow needs the adapter to authenticate the subject (authenticateSubject)');
        const authorization = await this.authorize(offer.offer, metadata.result, options.credentialConfigurationIds?.length ? options.credentialConfigurationIds : configurationId, evidence, {
          ...options,
          authenticate: options.authenticate,
        });
        if (options.stopAfterAuthorization) return evidence;
        token = await this.requestAuthorizationCodeToken(metadata.result, authorization, evidence, options.grantFault);
      } else {
        const other = options.otherOffer ? await this.resolveOffer(options.otherOffer.offer, evidence, { record: false }) : undefined;
        const otherCode = other?.offer.grants?.[PRE_AUTHORIZED_CODE_GRANT]?.['pre-authorized_code'];
        const { otherOffer: _other, ...rest } = options;
        token = await this.requestToken(offer.offer, metadata.result, evidence, options.txCode, {
          ...rest,
          ...(otherCode ? { otherOffer: { preAuthorizedCode: otherCode, ...(options.otherOffer?.txCode !== undefined ? { txCode: options.otherOffer.txCode } : {}) } } : {}),
        });
      }
      const configurationIds = options.credentialConfigurationIds?.length ? options.credentialConfigurationIds : [configurationId];
      for (const id of configurationIds) {
        const cNonce = await this.requestNonce(metadata.result, evidence);
        await this.requestCredential(metadata.result, token, id, cNonce, evidence, { byIdentifier: options.credentialIdentifier ?? false, ...(options.proof ? { proof: options.proof } : {}) });
      }
    } catch (error) {
      evidence.error = (error as Error).message;
      if (error instanceof WaitLimitExceeded) evidence.waitExceeded = { waitsFor: error.waitsFor, seconds: error.seconds, limit: error.limit };
    }
    return evidence;
  }

  private libraryClient(step: () => IssuanceStep, evidence: IssuanceEvidence): Openid4vciClient {
    return new Openid4vciClient({
      callbacks: {
        hash,
        fetch: recordingFetch(step, evidence.exchanges, this.options.hooks?.request),
        generateRandom: (length) => randomBytes(length),
        signJwt: notUsed,
        decryptJwe: notUsed,
        clientAuthentication: notUsed,
      },
    });
  }

  /** Resolves the offer by value or by reference (`SCN-I`), recording the fetch of `credential_offer_uri`. */
  async resolveOffer(input: string, evidence: IssuanceEvidence, options: { record?: boolean } = {}): Promise<OfferEvidence> {
    const normalised = input.startsWith('http') ? `${OFFER_SCHEME}?credential_offer_uri=${encodeURIComponent(input)}` : input;
    const params = new URL(normalised.replace(/^[^:]+:\/\/[^?]*/, 'https://offer.invalid/')).searchParams;
    const credentialOfferUri = params.get('credential_offer_uri') ?? undefined;
    const offer = await this.libraryClient(() => 'offer', evidence).resolveCredentialOffer(normalised);
    const resolved = { input, byReference: credentialOfferUri !== undefined, ...(credentialOfferUri ? { credentialOfferUri } : {}), offer };
    if (options.record !== false) evidence.offer = resolved;
    return resolved;
  }

  /**
   * Fetches the Credential Issuer metadata as JSON and the metadata of its Authorization Servers (`SCN-M`) through the
   * library, then the Credential Issuer metadata again with `Accept: application/jwt`.
   */
  async fetchMetadata(credentialIssuer: string, evidence: IssuanceEvidence, options: { signed?: boolean } = {}): Promise<MetadataEvidence> {
    const result = await this.libraryClient(() => 'metadata', evidence).resolveIssuerMetadata(credentialIssuer);
    evidence.metadata = { result };
    if (options.signed !== false) {
      const request = await this.hooked('metadata-jwt', signedMetadataRequest(credentialIssuerMetadataUrl(credentialIssuer)));
      evidence.metadata.signed = await send('metadata-jwt', request, evidence.exchanges);
    }
    return evidence.metadata;
  }

  /**
   * Token request with `pre-authorized_code` and `tx_code`, WIA, PoP and DPoP; one retry on `use_dpop_nonce`. A fault of
   * the point `token-request` changes the request (`applyTokenRequestFault`), sends ten wrong `tx_code` values first,
   * or waits past the declared lifetime of the code.
   */
  async requestToken(
    offer: CredentialOfferObject,
    metadata: IssuerMetadataResult,
    evidence: IssuanceEvidence,
    txCode?: string,
    options: Pick<IssueOptions, 'grantFault' | 'preAuthorizedCodeLifetimeSeconds' | 'maxWaitSeconds' | 'sleep'> & { otherOffer?: { preAuthorizedCode: string; txCode?: string } } = {},
  ): Promise<TokenResult> {
    const grant = offer.grants?.[PRE_AUTHORIZED_CODE_GRANT];
    if (!grant) throw new IssuanceError('the offer has no pre-authorized code grant');
    const { issuer } = this.authorizationServerOf(metadata, grant.authorization_server, evidence);
    const record: GrantEvidence = {
      grant: 'pre-authorized_code',
      clientId: this.unit.clientId,
      authorizationServer: issuer,
      preAuthorizedCode: grant['pre-authorized_code'],
      ...(txCode !== undefined ? { txCode } : {}),
      offerResolvedAt: new Date().toISOString(),
      ...(options.grantFault ? { fault: options.grantFault } : {}),
    };
    evidence.grant = record;
    if (options.grantFault === 'token-request.pre-authorized-code-expired') {
      if (options.preAuthorizedCodeLifetimeSeconds === undefined) throw new IssuanceError('the SUT declares no lifetime of its pre-authorized codes (ICS-14.pre_authorized_code)');
      record.waitedSeconds = await this.waitPast('pre-authorized-code', options.preAuthorizedCodeLifetimeSeconds, options);
    }
    const valid: TokenForm = { 'pre-authorized_code': grant['pre-authorized_code'], tx_code: txCode };
    if (options.grantFault === 'token-request.tx-code-repeated') {
      if (txCode === undefined) throw new IssuanceError('the offer has no tx_code to repeat wrongly');
      record.wrongTxCodeAttempts = 0;
      for (let attempt = 0; attempt < TX_CODE_WRONG_ATTEMPTS; attempt++) {
        await this.sendPreAuthorizedTokenRequest(issuer, { ...valid, tx_code: wrongTxCode(txCode) }, evidence);
        record.wrongTxCodeAttempts++;
      }
    }
    const form = applyTokenRequestFault(options.grantFault, valid, options);
    record.tokenRequest = form;
    return this.tokenResultOf(await this.sendPreAuthorizedTokenRequest(issuer, form, evidence), evidence);
  }

  /** Sends one token request of the pre-authorized code flow with the form's code and `tx_code`. */
  private async sendPreAuthorizedTokenRequest(issuer: string, form: TokenForm, evidence: IssuanceEvidence): Promise<HttpResponseRecord> {
    const as = this.tokenEndpointOf(evidence, issuer);
    const wia = await this.unit.wia();
    const build = async () =>
      tokenRequest({
        tokenEndpoint: as,
        preAuthorizedCode: form['pre-authorized_code'] ?? '',
        ...(form.tx_code !== undefined ? { txCode: form.tx_code } : {}),
        clientId: this.unit.clientId,
        clientAttestation: wia,
        clientAttestationPop: await this.pop(issuer),
        dpop: await this.dpop('token', 'POST', as),
      });
    return this.sendWithDpopRetry('token', build, evidence);
  }

  /** The token response as `TokenResult`, or an `IssuanceError` when the Authorization Server issued no token. */
  private tokenResultOf(response: HttpResponseRecord, evidence: IssuanceEvidence): TokenResult {
    const body = jsonOf(response);
    if (response.status !== 200 || typeof body?.access_token !== 'string') {
      throw new IssuanceError(`token request: HTTP ${response.status} ${response.body}`, evidence.exchanges.at(-1));
    }
    evidence.token = { accessToken: body.access_token, tokenType: typeof body.token_type === 'string' ? body.token_type : 'Bearer', response: body };
    return evidence.token;
  }

  // Authorization code flow (issuer harness design section 5.1): PAR with PKCE `S256`, `issuer_state` and
  // `authorization_details`, WIA, PoP and DPoP; the authorization request goes to the adapter's `authenticateSubject`;
  // then the token request with `code_verifier`. Faults of the points `authorization` and `token-request` apply.

  /** The Authorization Server of a grant, as `determineAuthorizationServerForCredentialOffer` chooses it. */
  private authorizationServerOf(metadata: IssuerMetadataResult, grantAuthorizationServer: string | undefined, evidence: IssuanceEvidence) {
    const issuer = determineAuthorizationServerForCredentialOffer({ issuerMetadata: metadata, grantAuthorizationServer });
    const server = metadata.authorizationServers.find((candidate) => candidate.issuer === issuer);
    if (!server?.token_endpoint) throw new IssuanceError(`authorization server ${issuer} has no token_endpoint`);
    evidence.authorizationServer = issuer;
    return { issuer, server };
  }

  private tokenEndpointOf(evidence: IssuanceEvidence, issuer: string): string {
    const endpoint = evidence.metadata?.result.authorizationServers.find((server) => server.issuer === issuer)?.token_endpoint;
    if (!endpoint) throw new IssuanceError(`authorization server ${issuer} has no token_endpoint`);
    return endpoint;
  }

  /**
   * PAR (or, for `authorization.no-par`, the plain authorization request) and the authorization request through the
   * adapter. Throws when the authorization response carries no code.
   */
  async authorize(
    offer: CredentialOfferObject,
    metadata: IssuerMetadataResult,
    configurationId: string | string[],
    evidence: IssuanceEvidence,
    options: Pick<IssueOptions, 'grantFault' | 'maxWaitSeconds' | 'sleep'> & { authenticate: Authenticate },
  ): Promise<AuthorizationEvidence> {
    const grant = offer.grants?.[AUTHORIZATION_CODE_GRANT];
    if (!grant) throw new IssuanceError('the offer has no authorization code grant');
    const { issuer, server } = this.authorizationServerOf(metadata, grant.authorization_server, evidence);
    if (!server.authorization_endpoint) throw new IssuanceError(`authorization server ${issuer} has no authorization_endpoint`);
    const codeVerifier = newCodeVerifier();
    const state = base64url.encode(randomBytes(16));
    const valid: AuthorizationParameters = {
      response_type: 'code',
      client_id: this.unit.clientId,
      redirect_uri: WALLET_REDIRECT_URI,
      state,
      issuer_state: grant.issuer_state,
      code_challenge: s256Challenge(codeVerifier),
      code_challenge_method: 'S256',
      authorization_details: JSON.stringify((Array.isArray(configurationId) ? configurationId : [configurationId]).map((id) => ({ type: 'openid_credential', credential_configuration_id: id }))),
    };
    const parameters = applyAuthorizationFault(options.grantFault, valid, { codeVerifier });
    const pushed = options.grantFault !== 'authorization.no-par';
    const authorization: AuthorizationEvidence = { authorizationServer: issuer, parameters, pushed, codeVerifier, redirectUri: WALLET_REDIRECT_URI, state };
    evidence.grant = { grant: 'authorization_code', clientId: this.unit.clientId, authorizationServer: issuer, authorization, ...(options.grantFault ? { fault: options.grantFault } : {}) };

    let url = authorizationRequestUrl(server.authorization_endpoint, parameters);
    if (pushed) {
      const endpoint = server.pushed_authorization_request_endpoint;
      if (!endpoint) throw new IssuanceError(`authorization server ${issuer} has no pushed_authorization_request_endpoint`);
      const wia = await this.unit.wia();
      const build = async () =>
        parRequest(endpoint, parameters, { clientAttestation: wia, clientAttestationPop: await this.pop(issuer, 'par'), dpop: await this.dpop('par', 'POST', endpoint) });
      const response = await this.sendWithDpopRetry('par', build, evidence);
      const body = jsonOf(response);
      if ((response.status !== 201 && response.status !== 200) || typeof body?.request_uri !== 'string') {
        throw new IssuanceError(`pushed authorization request: HTTP ${response.status} ${response.body}`, evidence.exchanges.at(-1));
      }
      authorization.requestUri = body.request_uri;
      if (typeof body.expires_in === 'number') authorization.expiresIn = body.expires_in;
      authorization.parAt = new Date().toISOString();
      if (options.grantFault === 'authorization.request-uri-expired') {
        if (authorization.expiresIn === undefined) throw new IssuanceError('the PAR response carries no expires_in');
        authorization.waitedSeconds = await this.waitPast('request-uri', authorization.expiresIn, options);
      }
      url = authorizationRequestUrl(server.authorization_endpoint, { client_id: this.unit.clientId, request_uri: body.request_uri });
    }
    await this.sendAuthorizationRequest(url, authorization, options.authenticate, evidence);
    return authorization;
  }

  /**
   * Hands the authorization request to the adapter and records its answer as the exchange of the step `authorization`:
   * the redirect to the wallet (recorded as HTTP 302 with its `Location`), or the answer that was not a redirect.
   */
  private async sendAuthorizationRequest(url: string, authorization: AuthorizationEvidence, authenticate: Authenticate, evidence: IssuanceEvidence): Promise<AuthorizationResponse> {
    const exchange: HttpExchange = { step: 'authorization', attempt: 1, at: new Date().toISOString(), request: { method: 'GET', url, headers: {} } };
    evidence.exchanges.push(exchange);
    authorization.url = url;
    authorization.sentAt = exchange.at;
    let location: string;
    try {
      location = await authenticate(url);
    } catch (error) {
      const answer = error as { status?: unknown; body?: unknown; headers?: unknown };
      if (typeof answer.status === 'number') {
        exchange.response = { status: answer.status, headers: (answer.headers as Record<string, string>) ?? {}, body: typeof answer.body === 'string' ? answer.body : '' };
        throw new IssuanceError(`authorization request: HTTP ${answer.status} without a redirect to the wallet ${exchange.response.body}`, exchange);
      }
      exchange.error = (error as Error).message;
      throw error;
    }
    exchange.response = { status: 302, headers: { location }, body: '' };
    const query = new URL(location).searchParams;
    const value = (name: string) => query.get(name) ?? undefined;
    const response: AuthorizationResponse = { location };
    for (const [key, name] of [['code', 'code'], ['state', 'state'], ['iss', 'iss'], ['error', 'error'], ['errorDescription', 'error_description']] as const) {
      const v = value(name);
      if (v !== undefined) response[key] = v;
    }
    authorization.response = response;
    if (!response.code) throw new IssuanceError(`authorization response without code: ${response.error ?? 'no error'} ${response.errorDescription ?? ''}`.trim(), exchange);
    return response;
  }

  /** Token request of the authorization code flow with the code, `code_verifier` and `redirect_uri` of `authorization`. */
  async requestAuthorizationCodeToken(metadata: IssuerMetadataResult, authorization: AuthorizationEvidence, evidence: IssuanceEvidence, fault?: GrantFaultId): Promise<TokenResult> {
    const code = authorization.response?.code;
    if (!code) throw new IssuanceError('no authorization code to redeem');
    const form = applyTokenRequestFault(fault, { code, code_verifier: authorization.codeVerifier, redirect_uri: authorization.redirectUri, client_id: this.unit.clientId });
    if (evidence.grant) evidence.grant.tokenRequest = form;
    return this.tokenResultOf(await this.sendAuthorizationCodeTokenRequest(metadata, authorization.authorizationServer, form, evidence), evidence);
  }

  private async sendAuthorizationCodeTokenRequest(metadata: IssuerMetadataResult, issuer: string, form: TokenForm, evidence: IssuanceEvidence): Promise<HttpResponseRecord> {
    const endpoint = metadata.authorizationServers.find((server) => server.issuer === issuer)?.token_endpoint;
    if (!endpoint) throw new IssuanceError(`authorization server ${issuer} has no token_endpoint`);
    const wia = await this.unit.wia();
    const build = async () =>
      authorizationCodeTokenRequest({
        tokenEndpoint: endpoint,
        code: form.code ?? '',
        ...(form.code_verifier !== undefined ? { codeVerifier: form.code_verifier } : {}),
        ...(form.redirect_uri !== undefined ? { redirectUri: form.redirect_uri } : {}),
        ...(form.client_id !== undefined ? { clientId: form.client_id } : {}),
        clientAttestation: wia,
        clientAttestationPop: await this.pop(issuer),
        dpop: await this.dpop('token', 'POST', endpoint),
      });
    return this.sendWithDpopRetry('token', build, evidence);
  }

  /**
   * `token-reuse` of a code (issuer harness design section 6.1): sends the token request of an earlier grant again, with
   * its pre-authorized code and `tx_code`, or its authorization code, `code_verifier` and `redirect_uri`, as this
   * client's Wallet Unit (its WIA, PoP, DPoP key and `client_id`). Never throws; errors land in the evidence.
   */
  async redeemAgain(metadata: MetadataEvidence, earlier: GrantEvidence): Promise<IssuanceEvidence> {
    const evidence: IssuanceEvidence = { walletUnit: this.unit.id, exchanges: [], credentials: [], metadata };
    try {
      const issuer = earlier.authorizationServer;
      if (!issuer) throw new IssuanceError('the earlier step reached no authorization server');
      evidence.authorizationServer = issuer;
      evidence.grant = { grant: earlier.grant, clientId: this.unit.clientId, authorizationServer: issuer };
      if (earlier.grant === 'pre-authorized_code') {
        const form: TokenForm = { 'pre-authorized_code': earlier.preAuthorizedCode, tx_code: earlier.txCode };
        evidence.grant.tokenRequest = form;
        this.tokenResultOf(await this.sendPreAuthorizedTokenRequest(issuer, form, evidence), evidence);
      } else {
        const authorization = earlier.authorization;
        if (!authorization?.response?.code) throw new IssuanceError('the earlier step obtained no authorization code');
        const form: TokenForm = { code: authorization.response.code, code_verifier: authorization.codeVerifier, redirect_uri: authorization.redirectUri, client_id: this.unit.clientId };
        evidence.grant.tokenRequest = form;
        this.tokenResultOf(await this.sendAuthorizationCodeTokenRequest(metadata.result, issuer, form, evidence), evidence);
      }
    } catch (error) {
      evidence.error = (error as Error).message;
    }
    return evidence;
  }

  /** `token-reuse` of a PAR `request_uri`: the authorization request of an earlier step again, through the adapter. */
  async reuseRequestUri(metadata: MetadataEvidence, earlier: GrantEvidence, authenticate: Authenticate): Promise<IssuanceEvidence> {
    const evidence: IssuanceEvidence = { walletUnit: this.unit.id, exchanges: [], credentials: [], metadata };
    try {
      const authorization = earlier.authorization;
      if (!authorization?.requestUri) throw new IssuanceError('the earlier step obtained no request_uri');
      const endpoint = metadata.result.authorizationServers.find((server) => server.issuer === authorization.authorizationServer)?.authorization_endpoint;
      if (!endpoint) throw new IssuanceError(`authorization server ${authorization.authorizationServer} has no authorization_endpoint`);
      const again: AuthorizationEvidence = { ...authorization, response: undefined };
      evidence.authorizationServer = authorization.authorizationServer;
      evidence.grant = { grant: 'authorization_code', clientId: this.unit.clientId, authorizationServer: authorization.authorizationServer, authorization: again };
      await this.sendAuthorizationRequest(authorizationRequestUrl(endpoint, { client_id: this.unit.clientId, request_uri: authorization.requestUri }), again, authenticate, evidence);
    } catch (error) {
      evidence.error = (error as Error).message;
    }
    return evidence;
  }

  /** Waits a lifetime plus one hour (catalogue section 3.5), or throws `WaitLimitExceeded` above the run's limit. */
  private async waitPast(waitsFor: 'request-uri' | 'pre-authorized-code', lifetimeSeconds: number, options: Pick<IssueOptions, 'maxWaitSeconds' | 'sleep'>): Promise<number> {
    const seconds = lifetimeSeconds + EXPIRY_MARGIN_SECONDS;
    const limit = options.maxWaitSeconds ?? 0;
    if (seconds > limit) throw new WaitLimitExceeded(waitsFor, seconds, limit);
    await (options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms))))(seconds * 1000);
    return seconds;
  }

  /** Fetches a `c_nonce` from the nonce endpoint. */
  async requestNonce(metadata: IssuerMetadataResult, evidence: IssuanceEvidence): Promise<string> {
    const endpoint = metadata.credentialIssuer.nonce_endpoint;
    if (!endpoint) throw new IssuanceError('the Credential Issuer metadata has no nonce_endpoint');
    const response = await send('nonce', await this.hooked('nonce', nonceRequest(endpoint)), evidence.exchanges);
    this.rememberDpopNonce(endpoint, response);
    const cNonce = jsonOf(response)?.c_nonce;
    if (response.status !== 200 || typeof cNonce !== 'string') throw new IssuanceError(`nonce request: HTTP ${response.status} ${response.body}`, evidence.exchanges.at(-1));
    evidence.cNonce = cNonce;
    return cNonce;
  }

  /**
   * Credential request by `credential_configuration_id`, with one `openid4vci-proof+jwt` signed by the first attested
   * key of a fresh KA and carrying that KA in `key_attestation`; DPoP with `ath`, one retry on `use_dpop_nonce`.
   */
  async requestCredential(
    metadata: IssuerMetadataResult,
    token: TokenResult,
    credentialConfigurationId: string,
    cNonce: string,
    evidence: IssuanceEvidence,
    options: { byIdentifier?: boolean; proof?: 'auto' | 'always' | 'never' } = {},
  ): Promise<IssuedCredential[]> {
    const configuration = metadata.credentialIssuer.credential_configurations_supported[credentialConfigurationId];
    // By `credential_identifier` (OpenID4VCI 1.0 section 8.2): the first one the token response issued for the configuration.
    const credentialIdentifier = options.byIdentifier ? credentialIdentifierOf(token, credentialConfigurationId) : undefined;
    if (!configuration) throw new IssuanceError(`the metadata has no credential configuration ${credentialConfigurationId}`);
    if (configuration.format !== 'dc+sd-jwt' && configuration.format !== 'mso_mdoc') {
      throw new IssuanceError(`format ${configuration.format}: the client requests SD-JWT VC (dc+sd-jwt) and mdoc (mso_mdoc) only`);
    }
    const endpoint = metadata.credentialIssuer.credential_endpoint;
    const ka = await this.unit.keyAttestation();
    const proofKey = ka.keys[0];
    const proof = await this.sign(
      'proof',
      'credential',
      keyProofParts({ key: proofKey, audience: metadata.credentialIssuer.credential_issuer, nonce: cNonce, keyAttestation: ka.jwt, clientId: this.unit.clientId }),
      proofKey,
    );

    const build = async () =>
      credentialRequest({
        credentialEndpoint: endpoint,
        accessToken: token.accessToken,
        tokenType: token.tokenType,
        dpop: await this.dpop('credential', 'POST', endpoint, token.accessToken),
        credentialConfigurationId,
        ...(credentialIdentifier !== undefined ? { credentialIdentifier } : {}),
        // Issue 27: no proof for a configuration without proof types (not device-bound), unless asked for.
        ...(options.proof === 'always' || (options.proof !== 'never' && configuration.proof_types_supported) ? { proofs: [proof] } : {}),
      });
    const response = await this.sendWithDpopRetry('credential', build, evidence);
    const body = jsonOf(response);
    const credentials = body?.credentials;
    if (response.status !== 200 || !Array.isArray(credentials)) {
      throw new IssuanceError(`credential request: HTTP ${response.status} ${response.body}`, evidence.exchanges.at(-1));
    }
    const issued = credentials.map((entry) => {
      const credential = (entry as { credential?: unknown }).credential;
      // SD-JWT VC: the compact SD-JWT; mdoc: base64url of IssuerSigned (OpenID4VCI Appendix A.1.2, A.2.4).
      if (typeof credential !== 'string') throw new IssuanceError(`a credentials entry carries no ${configuration.format} string`, evidence.exchanges.at(-1));
      return { credentialConfigurationId, format: configuration.format, credential, proofKey, keyAttestation: ka.jwt };
    });
    evidence.credentials.push(...issued);
    return issued;
  }

  /** The PoP of the unit's WIA for an Authorization Server: `iss` the `client_id`, `aud` its issuer, fresh `jti`. */
  private pop(audience: string, step: IssuanceStep = 'token') {
    return this.sign('wia-pop', step, wiaPopParts({ signer: keySigner(this.unit.instanceKey), clientId: this.unit.clientId, audience }), this.unit.instanceKey);
  }

  /** A DPoP proof with the unit's DPoP key, carrying the last `DPoP-Nonce` of the server, if any. */
  private dpop(step: IssuanceStep, method: string, url: string, accessToken?: string) {
    const nonce = this.dpopNonces.get(new URL(url).origin);
    return this.sign(
      'dpop',
      step,
      dpopProofParts({ key: this.dpopKey, method, url, ...(accessToken !== undefined ? { accessToken } : {}), ...(nonce !== undefined ? { nonce } : {}) }),
      this.dpopKey,
    );
  }

  private async sign(point: JwtPoint, step: IssuanceStep, parts: JwtParts, key: EcKeyPair): Promise<string> {
    const final = this.options.hooks?.jwt ? await this.options.hooks.jwt(point, parts, { step }) : parts;
    return signJwt(final, keySigner(key));
  }

  private async hooked(step: IssuanceStep, request: HttpRequestMessage): Promise<HttpRequestMessage> {
    return this.options.hooks?.request ? this.options.hooks.request(step, request) : request;
  }

  private rememberDpopNonce(url: string, response: HttpResponseRecord) {
    const nonce = response.headers['dpop-nonce'];
    if (nonce) this.dpopNonces.set(new URL(url).origin, nonce);
  }

  /**
   * Sends a request built by `build`; when the server answers `use_dpop_nonce` with a `DPoP-Nonce` (RFC 9449 sections
   * 8 and 9), rebuilds it once (fresh DPoP proof with the nonce, fresh PoP) and sends it again.
   */
  private async sendWithDpopRetry(step: IssuanceStep, build: () => Promise<HttpRequestMessage>, evidence: IssuanceEvidence): Promise<HttpResponseRecord> {
    const first = await this.hooked(step, await build());
    const response = await send(step, first, evidence.exchanges);
    this.rememberDpopNonce(first.url, response);
    if ((response.status === 400 || response.status === 401) && oauthErrorOf(response) === 'use_dpop_nonce' && response.headers['dpop-nonce']) {
      const retry = await this.hooked(step, await build());
      const second = await send(step, retry, evidence.exchanges, 2);
      this.rememberDpopNonce(retry.url, second);
      return second;
    }
    return response;
  }
}
