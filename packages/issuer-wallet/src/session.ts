// The issuance session after the offer (issue 25; issuer harness design section 5.1): token request with DPoP and the
// `use_dpop_nonce` retry, the refresh grant with the original DPoP key, the credential request with N proofs (one per
// attested key of a KA, a batch), optionally encrypted, a deferred response followed at the deferred credential endpoint,
// and the notification endpoint. A session keeps what later steps of a test case need (`token-reuse`, `notification`):
// metadata, access and refresh token, the `notification_id` and `transaction_id`, and the requests as sent.
//
// It uses `IssuanceClient` for offer and metadata and builds its own requests with the builders of requests.ts and
// jwts.ts, so every message passes the same seams (`MessageHooks`) and the session faults (session-faults.ts) can change
// any of them.
import { randomUUID } from 'node:crypto';
import { type CredentialOfferObject, determineAuthorizationServerForCredentialOffer, type IssuerMetadataResult } from '@openid4vc/openid4vci';
import type { EcKeyPair } from '@eudi-pcaf/forge';
import { type JwtParts, keySigner, signJwt, wiaPopParts } from '@eudi-pcaf/wallet-provider';
import { CLIENT_ATTESTATION_HEADER, CLIENT_ATTESTATION_POP_HEADER } from '@eudi-pcaf/wallet-provider';
import { type Authenticate, IssuanceClient, IssuanceError, type IssuanceEvidence, type JwtPoint, type KeyAttestationWithKeys, type MessageHooks, type WalletUnitBinding } from './client';
import { type HttpExchange, type HttpRequestMessage, type HttpResponseRecord, type IssuanceStep, jsonOf, oauthErrorOf, send } from './http';
import { decryptJwe, encryptJwe, generateEncryptionKey } from './jwe';
import { dpopProofParts, keyProofParts } from './jwts';
import { AUTHORIZATION_CODE_GRANT, nonceRequest, PRE_AUTHORIZED_CODE_GRANT, tokenRequest } from './requests';

export const REFRESH_TOKEN_GRANT = 'refresh_token';

/** Changes the JSON body of a request before it is encrypted and sent (credential, notification, deferred). */
export type BodyHook = (step: IssuanceStep, body: Record<string, unknown>) => Record<string, unknown> | Promise<Record<string, unknown>>;

export interface SessionHooks extends MessageHooks {
  body?: BodyHook;
}

export interface SessionClientOptions {
  allowInsecureUrls?: boolean;
  hooks?: SessionHooks;
  /** The DPoP key; default a fresh one (one per Wallet Unit, design section 5.1). */
  dpopKey?: EcKeyPair;
  /** Do not answer `use_dpop_nonce` with a retry (`dpop.nonce-omitted`). */
  noDpopRetry?: boolean;
}

/** What the session holds after the token response, for the credential request and for later steps. */
export interface SessionState {
  offer: CredentialOfferObject;
  metadata: IssuerMetadataResult;
  authorizationServer: string;
  tokenEndpoint: string;
  credentialConfigurationId: string;
  accessToken?: string;
  tokenType?: string;
  refreshToken?: string;
  /** The key the access token and refresh token are bound to: the DPoP key of the token request. */
  boundKey?: JsonWebKey;
  tokenResponse?: Record<string, unknown>;
  cNonce?: string;
  notificationIds: string[];
  transactionId?: string;
  /** `jti` values of every DPoP proof the session sent. */
  dpopJtis: string[];
}

/** A credential the session received. */
export interface SessionCredential {
  credentialConfigurationId: string;
  format: string;
  credential: string;
  /** The proof key of the proof at the same position in the request (a batch answers in proof order). */
  proofKey: EcKeyPair;
  /** Every proof key of the request, for the holder binding of a batch. */
  proofKeys: EcKeyPair[];
  keyAttestation: string;
}

/** Evidence of a session step: the exchanges, and the plaintext of encrypted requests and responses. */
export interface SessionEvidence extends Omit<IssuanceEvidence, 'credentials'> {
  credentials: SessionCredential[];
  /** The JSON bodies the session encrypted, by step, as built (after the body hook). */
  plaintext: { step: IssuanceStep; body: string }[];
  /** The credential response decrypted, when it was encrypted. */
  decryptedResponse?: string;
  notificationId?: string;
  transactionId?: string;
  /** The deferred response (HTTP 202), how often the session polled, and how many polls answered `issuance_pending`. */
  deferred?: { interval?: number; polls: number; pending: number };
}

export interface CredentialRequestOptions {
  /** Number of proofs (default 1), each signed by another key of one KA over `keys` keys. */
  proofs?: number;
  /** Number of keys of the KA; default `proofs`. */
  keys?: number;
  /** The attested key that signs proof `i`; default key `i`. */
  keyIndex?: (i: number) => number;
  /** Encrypt the request to the Credential Issuer and ask for an encrypted response. */
  encryption?: boolean;
  /** Follow a deferred response at the deferred credential endpoint; default true. */
  followDeferred?: boolean;
  /** Most polls of the deferred credential endpoint; default 10. */
  maxPolls?: number;
  /** Called with the `transaction_id` when a poll answers `issuance_pending` (the adapter completes the issuance). */
  onPending?: (transactionId: string) => Promise<void>;
  sleep?: (ms: number) => Promise<void>;
}

/** A KA over `count` fresh keys of the Wallet Unit. */
export type KeyAttestationSource = (count: number) => Promise<KeyAttestationWithKeys>;

const wait = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export class SessionClient {
  private readonly dpopNonces = new Map<string, string>();

  private constructor(
    readonly unit: WalletUnitBinding,
    readonly dpopKey: EcKeyPair,
    private readonly keyAttestation: KeyAttestationSource,
    private readonly base: IssuanceClient,
    private readonly options: SessionClientOptions,
  ) {}

  static async create(unit: WalletUnitBinding, keyAttestation: KeyAttestationSource, options: SessionClientOptions = {}): Promise<SessionClient> {
    const base = await IssuanceClient.create(unit, { ...(options.allowInsecureUrls ? { allowInsecureUrls: true } : {}), ...(options.hooks ? { hooks: options.hooks } : {}) });
    // Without a given key the session signs with the DPoP key of its IssuanceClient, which runs PAR and the token request
    // of the authorization code flow: code, access token and credential request are then bound to one key.
    return new SessionClient(unit, options.dpopKey ?? base.dpopKey, keyAttestation, base, options);
  }

  /** A client of the same Wallet Unit and DPoP key with other hooks (the fault of a later step). */
  with(options: Pick<SessionClientOptions, 'hooks' | 'noDpopRetry'> & { unit?: WalletUnitBinding; keyAttestation?: KeyAttestationSource }): Promise<SessionClient> {
    const { unit, keyAttestation, ...rest } = options;
    return SessionClient.create(unit ?? this.unit, keyAttestation ?? this.keyAttestation, { ...this.options, ...rest, dpopKey: this.dpopKey });
  }

  static newEvidence(walletUnit: string): SessionEvidence {
    return { walletUnit, exchanges: [], credentials: [], plaintext: [] };
  }

  /** Offer and metadata (`SCN-M`, without the signed metadata) and the Authorization Server of the pre-authorized grant. */
  async start(offerInput: string, evidence: SessionEvidence, credentialConfigurationId?: string): Promise<SessionState> {
    const offer = await this.base.resolveOffer(offerInput, evidence as unknown as IssuanceEvidence);
    const metadata = await this.base.fetchMetadata(offer.offer.credential_issuer, evidence as unknown as IssuanceEvidence, { signed: false });
    const grant = offer.offer.grants?.[PRE_AUTHORIZED_CODE_GRANT] ?? offer.offer.grants?.[AUTHORIZATION_CODE_GRANT];
    if (!grant) throw new IssuanceError('the offer has neither a pre-authorized code nor an authorization code grant');
    const issuer = determineAuthorizationServerForCredentialOffer({ issuerMetadata: metadata.result, grantAuthorizationServer: grant.authorization_server });
    const as = metadata.result.authorizationServers.find((server) => server.issuer === issuer);
    if (!as?.token_endpoint) throw new IssuanceError(`authorization server ${issuer} has no token_endpoint`);
    evidence.authorizationServer = issuer;
    return {
      offer: offer.offer,
      metadata: metadata.result,
      authorizationServer: issuer,
      tokenEndpoint: as.token_endpoint,
      credentialConfigurationId: credentialConfigurationId ?? offer.offer.credential_configuration_ids[0],
      notificationIds: [],
      dpopJtis: [],
    };
  }

  /** Token request of the pre-authorized code grant with WIA, PoP and DPoP (`SCN-I`). */
  async token(state: SessionState, evidence: SessionEvidence, txCode?: string): Promise<void> {
    const grant = state.offer.grants?.[PRE_AUTHORIZED_CODE_GRANT];
    const wia = await this.unit.wia();
    const build = async () =>
      tokenRequest({
        tokenEndpoint: state.tokenEndpoint,
        preAuthorizedCode: grant!['pre-authorized_code'],
        ...(txCode !== undefined ? { txCode } : {}),
        clientId: this.unit.clientId,
        clientAttestation: wia,
        clientAttestationPop: await this.pop(state.authorizationServer),
        dpop: await this.dpop(state, 'token', 'POST', state.tokenEndpoint),
      });
    const response = await this.sendWithDpopRetry('token', build, evidence);
    this.acceptToken(state, response, evidence, 'token');
  }

  /**
   * The authorization code flow (issue 20's `authorize`): PAR with PKCE, the authorization request through the adapter's
   * `authenticateSubject`, and the token request with the code, all with the session's DPoP key.
   */
  async authorizationCode(state: SessionState, evidence: SessionEvidence, authenticate: Authenticate): Promise<void> {
    const shared = evidence as unknown as IssuanceEvidence;
    const authorization = await this.base.authorize(state.offer, state.metadata, state.credentialConfigurationId, shared, { authenticate });
    const token = await this.base.requestAuthorizationCodeToken(state.metadata, authorization, shared);
    state.accessToken = token.accessToken;
    state.tokenType = token.tokenType;
    if (typeof token.response.refresh_token === 'string') state.refreshToken = token.response.refresh_token;
    state.boundKey = this.dpopKey.publicJwk;
    state.tokenResponse = token.response;
    evidence.token = token;
  }

  /** The refresh grant (RFC 6749 section 6) with the refresh token of the session, WIA, PoP and the session's DPoP key. */
  async refresh(state: SessionState, evidence: SessionEvidence): Promise<void> {
    if (!state.refreshToken) throw new IssuanceError('the token response issued no refresh_token');
    const refreshToken = state.refreshToken;
    const wia = await this.unit.wia();
    const build = async (): Promise<HttpRequestMessage> => {
      const form = new URLSearchParams({ grant_type: REFRESH_TOKEN_GRANT, refresh_token: refreshToken, client_id: this.unit.clientId });
      return {
        method: 'POST',
        url: state.tokenEndpoint,
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
          [CLIENT_ATTESTATION_HEADER]: wia,
          [CLIENT_ATTESTATION_POP_HEADER]: await this.pop(state.authorizationServer, 'refresh'),
          DPoP: await this.dpop(state, 'refresh', 'POST', state.tokenEndpoint),
        },
        body: form.toString(),
      };
    };
    const response = await this.sendWithDpopRetry('refresh', build, evidence);
    this.acceptToken(state, response, evidence, 'refresh');
  }

  private acceptToken(state: SessionState, response: HttpResponseRecord, evidence: SessionEvidence, step: 'token' | 'refresh') {
    const body = jsonOf(response);
    if (response.status !== 200 || typeof body?.access_token !== 'string') {
      throw new IssuanceError(`${step === 'token' ? 'token' : 'refresh token'} request: HTTP ${response.status} ${response.body}`, evidence.exchanges.at(-1));
    }
    state.accessToken = body.access_token;
    state.tokenType = typeof body.token_type === 'string' ? body.token_type : 'Bearer';
    // A refresh response without a refresh token leaves the earlier one in use (RFC 6749 section 6).
    if (typeof body.refresh_token === 'string') state.refreshToken = body.refresh_token;
    state.boundKey = this.dpopKey.publicJwk;
    state.tokenResponse = body;
    evidence.token = { accessToken: body.access_token, tokenType: state.tokenType, response: body };
  }

  /** A `c_nonce` from the nonce endpoint. */
  async nonce(state: SessionState, evidence: SessionEvidence): Promise<string> {
    const endpoint = state.metadata.credentialIssuer.nonce_endpoint;
    if (!endpoint) throw new IssuanceError('the Credential Issuer metadata has no nonce_endpoint');
    const response = await send('nonce', await this.hooked('nonce', nonceRequest(endpoint)), evidence.exchanges);
    this.rememberDpopNonce(endpoint, response);
    const cNonce = jsonOf(response)?.c_nonce;
    if (response.status !== 200 || typeof cNonce !== 'string') throw new IssuanceError(`nonce request: HTTP ${response.status} ${response.body}`, evidence.exchanges.at(-1));
    state.cNonce = cNonce;
    evidence.cNonce = cNonce;
    return cNonce;
  }

  /**
   * Credential request by `credential_configuration_id` with `proofs` key proofs, each signed by another attested key of
   * one fresh KA and carrying it; encrypted on request; a deferred response (HTTP 202) is followed at the deferred
   * credential endpoint.
   */
  async credential(state: SessionState, evidence: SessionEvidence, options: CredentialRequestOptions = {}): Promise<SessionCredential[]> {
    const issuer = state.metadata.credentialIssuer;
    const configuration = issuer.credential_configurations_supported[state.credentialConfigurationId];
    if (!configuration) throw new IssuanceError(`the metadata has no credential configuration ${state.credentialConfigurationId}`);
    if (configuration.format !== 'dc+sd-jwt') throw new IssuanceError(`format ${configuration.format}: the client requests SD-JWT VC (dc+sd-jwt) only`);
    const cNonce = state.cNonce ?? (await this.nonce(state, evidence));
    const count = options.proofs ?? 1;
    const ka = await this.keyAttestation(options.keys ?? count);
    const keyOf = (i: number) => ka.keys[options.keyIndex ? options.keyIndex(i) : i];
    const proofs: string[] = [];
    for (let i = 0; i < count; i += 1) {
      const key = keyOf(i);
      proofs.push(
        await this.sign('proof', 'credential', keyProofParts({ key, audience: issuer.credential_issuer, nonce: cNonce, keyAttestation: ka.jwt, clientId: this.unit.clientId }), key),
      );
    }
    let body: Record<string, unknown> = { credential_configuration_id: state.credentialConfigurationId, proofs: { jwt: proofs } };
    const responseKey = options.encryption ? generateEncryptionKey() : undefined;
    if (responseKey) {
      const enc = this.responseEncryption(state).enc_values_supported?.[0] ?? 'A128GCM';
      body.credential_response_encryption = { jwk: { ...responseKey.publicJwk, alg: 'ECDH-ES', use: 'enc', kid: randomUUID() }, enc };
    }
    body = await this.hookedBody('credential', body);
    const endpoint = issuer.credential_endpoint;
    const build = async () => this.resourceRequest(state, 'credential', endpoint, body, options.encryption ?? false, evidence);
    const response = await this.sendWithDpopRetry('credential', build, evidence);
    let json = this.readResponse(response, responseKey?.privateJwk, evidence);
    if (response.status === 202 && typeof json?.transaction_id === 'string') {
      state.transactionId = json.transaction_id;
      evidence.transactionId = json.transaction_id;
      const interval = typeof json.interval === 'number' ? json.interval : 5;
      evidence.deferred = { interval: typeof json.interval === 'number' ? json.interval : undefined, polls: 0, pending: 0 };
      if (options.followDeferred === false) return [];
      json = await this.pollDeferred(state, evidence, {
        interval,
        maxPolls: options.maxPolls ?? 10,
        sleep: options.sleep ?? wait,
        encryption: options.encryption ?? false,
        ...(options.onPending ? { onPending: options.onPending } : {}),
      });
    } else if (response.status !== 200) {
      throw new IssuanceError(`credential request: HTTP ${response.status} ${response.body}`, evidence.exchanges.at(-1));
    }
    return this.acceptCredentials(state, json, configuration.format, ka, proofs.map((_, i) => keyOf(i)), evidence);
  }

  /** Redeems the session's `transaction_id` at the deferred credential endpoint until it is no longer pending. */
  async pollDeferred(
    state: SessionState,
    evidence: SessionEvidence,
    options: {
      interval: number;
      maxPolls: number;
      sleep: (ms: number) => Promise<void>;
      encryption: boolean;
      transactionId?: string;
      onPending?: (transactionId: string) => Promise<void>;
    },
  ): Promise<Record<string, unknown> | undefined> {
    const endpoint = state.metadata.credentialIssuer.deferred_credential_endpoint;
    if (!endpoint) throw new IssuanceError('the Credential Issuer metadata has no deferred_credential_endpoint');
    const deferred = (evidence.deferred ??= { interval: options.interval, polls: 0, pending: 0 });
    const transactionId = options.transactionId ?? state.transactionId;
    for (let poll = 0; poll < options.maxPolls; poll += 1) {
      deferred.polls += 1;
      const body = await this.hookedBody('deferred', { transaction_id: transactionId });
      const response = await this.sendWithDpopRetry('deferred', () => this.resourceRequest(state, 'deferred', endpoint, body, false, evidence), evidence);
      const json = jsonOf(response);
      if (response.status === 200) return json;
      if (response.status === 400 && json?.error === 'issuance_pending') {
        deferred.pending += 1;
        if (transactionId) await options.onPending?.(transactionId);
        await options.sleep((typeof json.interval === 'number' ? json.interval : options.interval) * 1000);
        continue;
      }
      throw new IssuanceError(`deferred credential request: HTTP ${response.status} ${response.body}`, evidence.exchanges.at(-1));
    }
    throw new IssuanceError(`the deferred credential was still pending after ${options.maxPolls} polls`);
  }

  /** Sends a notification (OpenID4VCI 1.0 section 11.1) for a `notification_id` of the session. */
  async notify(state: SessionState, evidence: SessionEvidence, event: string, notificationId?: string): Promise<HttpResponseRecord> {
    const endpoint = state.metadata.credentialIssuer.notification_endpoint;
    if (!endpoint) throw new IssuanceError('the Credential Issuer metadata has no notification_endpoint');
    const id = notificationId ?? state.notificationIds.at(-1);
    if (!id) throw new IssuanceError('the credential response issued no notification_id');
    const body = await this.hookedBody('notification', { notification_id: id, event });
    return this.sendWithDpopRetry('notification', () => this.resourceRequest(state, 'notification', endpoint, body, false, evidence), evidence);
  }

  private responseEncryption(state: SessionState) {
    return ((state.metadata.credentialIssuer as Record<string, unknown>).credential_response_encryption ?? {}) as { alg_values_supported?: string[]; enc_values_supported?: string[] };
  }

  /** A request to a resource of the Credential Issuer: the access token with its scheme and a DPoP proof with `ath`. */
  private async resourceRequest(state: SessionState, step: IssuanceStep, url: string, body: Record<string, unknown>, encrypt: boolean, evidence: SessionEvidence): Promise<HttpRequestMessage> {
    if (!state.accessToken) throw new IssuanceError('the session has no access token');
    const json = JSON.stringify(body);
    let payload = json;
    let contentType = 'application/json';
    if (encrypt) {
      const encryption = (state.metadata.credentialIssuer as Record<string, unknown>).credential_request_encryption as
        | { jwks?: { keys?: (JsonWebKey & { kid?: string })[] }; enc_values_supported?: string[] }
        | undefined;
      const key = encryption?.jwks?.keys?.[0];
      if (!key) throw new IssuanceError('the Credential Issuer advertises no credential_request_encryption key');
      payload = encryptJwe(json, key, encryption?.enc_values_supported?.[0] ?? 'A128GCM', key.kid ? { kid: key.kid } : {});
      contentType = 'application/jwt';
      evidence.plaintext.push({ step, body: json });
    }
    return {
      method: 'POST',
      url,
      headers: {
        'content-type': contentType,
        accept: 'application/json',
        authorization: `${state.tokenType ?? 'DPoP'} ${state.accessToken}`,
        DPoP: await this.dpop(state, step, 'POST', url, state.accessToken),
      },
      body: payload,
    };
  }

  /** The JSON of a response; an `application/jwt` response is decrypted with the response encryption key. */
  private readResponse(response: HttpResponseRecord, key: JsonWebKey | undefined, evidence: SessionEvidence): Record<string, unknown> | undefined {
    const contentType = (response.headers['content-type'] ?? '').split(';')[0].trim();
    if (key && response.status < 300 && (contentType === 'application/jwt' || response.body.split('.').length === 5)) {
      const { plaintext } = decryptJwe(response.body.trim(), key);
      evidence.decryptedResponse = plaintext;
      return JSON.parse(plaintext) as Record<string, unknown>;
    }
    return jsonOf(response);
  }

  private acceptCredentials(
    state: SessionState,
    json: Record<string, unknown> | undefined,
    format: string,
    ka: KeyAttestationWithKeys,
    keys: EcKeyPair[],
    evidence: SessionEvidence,
  ): SessionCredential[] {
    const credentials = json?.credentials;
    if (!Array.isArray(credentials)) throw new IssuanceError('the credential response carries no credentials array', evidence.exchanges.at(-1));
    if (typeof json?.notification_id === 'string') {
      state.notificationIds.push(json.notification_id);
      evidence.notificationId = json.notification_id;
    }
    const issued = credentials.map((entry, i) => {
      const credential = (entry as { credential?: unknown }).credential;
      if (typeof credential !== 'string') throw new IssuanceError('a credentials entry carries no SD-JWT VC string', evidence.exchanges.at(-1));
      return { credentialConfigurationId: state.credentialConfigurationId, format, credential, proofKey: keys[i] ?? keys[0], proofKeys: keys, keyAttestation: ka.jwt };
    });
    evidence.credentials.push(...issued);
    return issued;
  }

  private pop(audience: string, step: IssuanceStep = 'token') {
    return this.sign('wia-pop', step, wiaPopParts({ signer: keySigner(this.unit.instanceKey), clientId: this.unit.clientId, audience }), this.unit.instanceKey);
  }

  private async dpop(state: SessionState, step: IssuanceStep, method: string, url: string, accessToken?: string) {
    const nonce = this.dpopNonces.get(new URL(url).origin);
    const parts = dpopProofParts({ key: this.dpopKey, method, url, ...(accessToken !== undefined ? { accessToken } : {}), ...(nonce !== undefined ? { nonce } : {}) });
    state.dpopJtis.push(parts.payload.jti as string);
    return this.sign('dpop', step, parts, this.dpopKey);
  }

  private async sign(point: JwtPoint, step: IssuanceStep, parts: JwtParts, key: EcKeyPair): Promise<string> {
    const final = this.options.hooks?.jwt ? await this.options.hooks.jwt(point, parts, { step }) : parts;
    return signJwt(final, keySigner(key));
  }

  private async hooked(step: IssuanceStep, request: HttpRequestMessage): Promise<HttpRequestMessage> {
    return this.options.hooks?.request ? this.options.hooks.request(step, request) : request;
  }

  private async hookedBody(step: IssuanceStep, body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.options.hooks?.body ? this.options.hooks.body(step, body) : body;
  }

  private rememberDpopNonce(url: string, response: HttpResponseRecord) {
    const nonce = response.headers['dpop-nonce'];
    if (nonce) this.dpopNonces.set(new URL(url).origin, nonce);
  }

  /** Sends a request; on `use_dpop_nonce` with a `DPoP-Nonce` (RFC 9449 sections 8 and 9) rebuilds and sends it once more. */
  private async sendWithDpopRetry(step: IssuanceStep, build: () => Promise<HttpRequestMessage>, evidence: SessionEvidence): Promise<HttpResponseRecord> {
    const first = await this.hooked(step, await build());
    const response = await send(step, first, evidence.exchanges);
    this.rememberDpopNonce(first.url, response);
    if (!this.options.noDpopRetry && (response.status === 400 || response.status === 401) && oauthErrorOf(response) === 'use_dpop_nonce' && response.headers['dpop-nonce']) {
      const retry = await this.hooked(step, await build());
      const second = await send(step, retry, evidence.exchanges, 2);
      this.rememberDpopNonce(retry.url, second);
      return second;
    }
    return response;
  }
}

/** The exchanges of a session evidence from `index` on: what one step of a test case sent. */
export const exchangesSince = (evidence: { exchanges: HttpExchange[] }, index: number) => evidence.exchanges.slice(index);
