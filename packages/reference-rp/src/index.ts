import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { type CallbackContext, type Jwk, setGlobalConfig } from '@openid4vc/oauth2';
import { Openid4vpVerifier } from '@openid4vc/openid4vp';
import type {
  DcqlQuery,
  DefaultQueryId,
  Flow,
  KeyedCertificate,
  PublishedListOfTrustedLists,
  RulebookTrust,
  RunningServer,
  ServerOptions,
} from '@rp-conformance/core';
import { categoryOfCredentialQuery, sendJson, sendText, startServer } from '@rp-conformance/core';
import { base64url, decodeCbor, jwkThumbprint, type Oid4vpHandover, PID_DOCTYPE, PID_VCT, readCose, signCompactJws } from '@rp-conformance/forge';
import type { CheckResult } from '@rp-conformance/core';
import {
  type FetchedStatusList,
  type ListSource,
  type MdocValidation,
  type SdJwtVcValidation,
  type StatusListFreshness,
  TRUST_RULES,
  TrustStore,
  validateAuthorizationResponse,
  validateMdocPresentation,
  validateCombinedBinding,
  validateSdJwtVcPresentation,
  validateVpToken,
} from '@rp-conformance/validator';
import { exportJWK, generateKeyPair, importJWK } from 'jose';

export interface ReferenceRpOptions extends ServerOptions {
  /** Base URL under which the Conformance Wallet reaches the Relying Party. */
  publicBaseUrl?: string;
  trustLists: ListSource[];
  /** The test LOTL that points to `TL-QEAA`. */
  listOfTrustedLists?: PublishedListOfTrustedLists;
  /** The anchors the rulebook of `default_credential_eaa` defines. */
  rulebooks?: RulebookTrust[];
  accessCertificate: KeyedCertificate;
  registrationCertificate: string;
  queries: Record<DefaultQueryId, DcqlQuery>;
  /** `T_skew`, seconds. */
  skewSeconds: number;
  /** `T_kb`, seconds. */
  kbMaxAgeSeconds: number;
  /** Maximum decompressed size of a status list, bytes (ICS RP.R.4). */
  maxStatusListBytes: number;
  /** Status values besides 0x00 treated as VALID (ICS RP.R.3); default none. */
  validStatuses?: number[];
  /** Lets the OpenID4VP library use `http` URLs, for runs on localhost. */
  allowInsecureUrls?: boolean;
  /** The grace period `G` after the `NextUpdate` of a trust list (ICS RP.T.2), milliseconds; default 0. */
  graceMs?: number;
  /** The maximum size of an Authorization Response (ICS RP.P.11), bytes; a larger request body is refused with 413. */
  maxResponseBytes?: number;
  /** Cache Status List Tokens for their `ttl` (ICS RP.R.5). */
  cacheStatusLists?: boolean;
  /** Timeout of a status list or identifier list retrieval (ICS RP.R.6), milliseconds; default 5000. */
  statusTimeoutMs?: number;
  /** Freshness policy for Status List Tokens (ICS RP.R.7, RP.R.8). */
  statusListFreshness?: StatusListFreshness;
  /** Reject a PID whose administrative expiry date has passed (ICS RP.P.12). */
  rejectPastExpiryDate?: boolean;
  /** Require the signing certificate of an SD-JWT VC to name its `iss` (ICS RP.P.13). */
  requireIssuerInCertificate?: boolean;
  /** The transaction lifetime `T_tx` (ICS RP.P.7), milliseconds; default 300 s. */
  transactionLifetimeMs?: number;
}

export type TransactionStatus = 'pending' | 'success' | 'failure';

/** The protocol of the reference Relying Party's DC API requests: a signed request object (OpenID4VP 1.0 Appendix A.3.2.1). */
export const DC_API_PROTOCOL = 'openid4vp-v1-signed';

interface Transaction {
  id: string;
  query: DefaultQueryId;
  flow: Flow;
  status: TransactionStatus;
  createdAt: string;
  requestJwt: string;
  requestPayload: Record<string, unknown>;
  encryptionKey: CryptoKey;
  encryptionJwk: Jwk;
  attributes?: Record<string, unknown>;
  /** Conditions the result signals, for example `trust-list-stale`. */
  flags?: string[];
  error?: string;
  response?: CheckResult[];
  validations?: (SdJwtVcValidation | MdocValidation)[];
  /** The user session (a cookie of the user agent) that started the transaction at the front end. */
  userSession: string;
  /** Via redirects: the response code of the `redirect_uri`, set when the response was accepted. */
  responseCode?: string;
  /** Whether the front end released the result for the response code. */
  redeemed?: boolean;
}

/** The cookie by which the reference Relying Party's front end recognises the user agent that started a transaction. */
export const USER_SESSION_COOKIE = 'rp_session';

/** The verification result the reference Relying Party exposes for a transaction (its ICS item RP.G.6: API). */
export interface ReferenceRpResult {
  transactionId: string;
  status: TransactionStatus;
  /** Released attributes by claim path joined with `.`. */
  attributes?: Record<string, unknown>;
  /** Conditions the result signals: `trust-list-stale` when a trust list it relied on is used within its grace period. */
  flags?: string[];
  error?: string;
  /** The checks of the Authorization Response. */
  response?: CheckResult[];
  validations?: (SdJwtVcValidation | MdocValidation)[];
}

const hash: CallbackContext['hash'] = (data, alg) => createHash(alg.replace('-', '').toLowerCase()).update(data).digest();

/**
 * Whether a host is an address the reference Relying Party never requests a status list from: a link-local or private
 * IPv4 or IPv6 literal (RP_PP_IA_Supportive_006). Loopback stays allowed, since the harness itself runs on 127.0.0.1.
 */
export function isBlockedHost(hostname: string): boolean {
  const host = hostname.replace(/^\[(.*)\]$/, '$1').toLowerCase();
  const v4 = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(host)?.slice(1).map(Number);
  if (v4) {
    const [a, b] = v4 as [number, number];
    return a === 10 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 0;
  }
  return /^fe[89ab][0-9a-f]:/.test(host) || /^f[cd][0-9a-f]{2}:/.test(host);
}

/** Fetches a status list or identifier list: text for a JWT, bytes for a CWT. */
async function fetchList(uri: string, accept: string, timeoutMs = 5000): Promise<FetchedStatusList> {
  if (isBlockedHost(new URL(uri).hostname)) throw new Error(`the status list URI names the link-local or private address ${new URL(uri).hostname}`);
  const fetched = await fetch(uri, { headers: { accept }, signal: AbortSignal.timeout(timeoutMs) });
  const bytes = new Uint8Array(await fetched.arrayBuffer());
  return { status: fetched.status, body: accept.endsWith('+jwt') ? new TextDecoder().decode(bytes) : bytes, contentType: fetched.headers.get('content-type') };
}

/** `x509_hash` Client Identifier (OpenID4VP 1.0 section 5.9.3): base64url SHA-256 of the DER leaf certificate. */
export function x509HashClientId(certificateBase64Der: string): string {
  return `x509_hash:${base64url.encode(createHash('sha256').update(Buffer.from(certificateBase64Der, 'base64')).digest())}`;
}

/**
 * A minimal Relying Party built on the reference validator (harness design section 7). It signs its request with
 * its access certificate (`x509_hash`), asks for `direct_post.jwt` via redirects or `dc_api.jwt` via the W3C Digital
 * Credentials API (from a page of its own, `/dc-api/<id>`), verifies the presentation with the reference validator
 * against the trust configuration it loads from the Test Trust Infrastructure (the LoTEs, the LOTL and `TL-QEAA`) and
 * the rulebook anchors it is configured with, and exposes its verification result through an API.
 */
export class ReferenceRelyingParty {
  private server?: RunningServer;
  private baseUrl = '';
  private readonly transactions = new Map<string, Transaction>();
  readonly trust: TrustStore;
  readonly clientId: string;
  private accessKey?: CryptoKey;
  /** Status List Tokens by URI, until their `ttl` has passed (ICS RP.R.5). */
  private readonly statusCache = new Map<string, { fetched: FetchedStatusList; expiresAt: number }>();

  constructor(private readonly options: ReferenceRpOptions) {
    this.trust = new TrustStore({
      lotes: options.trustLists,
      listOfTrustedLists: options.listOfTrustedLists,
      rulebooks: options.rulebooks,
    }, fetch, { graceMs: options.graceMs ?? 0 });
    this.clientId = x509HashClientId(options.accessCertificate.certificate);
  }

  get url(): string {
    return this.baseUrl;
  }

  /** The Origin of the Relying Party's pages, which its DC API requests name in `expected_origins`. */
  get origin(): string {
    return new URL(this.baseUrl).origin;
  }

  async start(): Promise<this> {
    if (this.options.allowInsecureUrls) setGlobalConfig({ allowInsecureUrls: true });
    this.accessKey = (await importJWK(this.options.accessCertificate.privateJwk as never, 'ES256')) as CryptoKey;
    this.server = await startServer(this.options, (req, res, body) => this.route(req.method ?? 'GET', req.url ?? '/', body, res, req.headers));
    this.baseUrl = (this.options.publicBaseUrl ?? this.server.localUrl).replace(/\/$/, '');
    await this.refreshTrust();
    return this;
  }

  async stop() {
    await this.server?.close();
  }

  async refreshTrust() {
    return this.trust.refresh();
  }

  /** A Status List Token from the cache while its `ttl` lasts, otherwise retrieved (ICS RP.R.5, RP.R.6). */
  private async fetchStatusList(uri: string, accept: string): Promise<FetchedStatusList> {
    const cached = this.statusCache.get(uri);
    if (cached && cached.expiresAt > Date.now()) return cached.fetched;
    const fetched = await fetchList(uri, accept, this.options.statusTimeoutMs);
    const ttl = this.options.cacheStatusLists && fetched.status === 200 ? ttlOf(fetched.body) : undefined;
    if (ttl) this.statusCache.set(uri, { fetched, expiresAt: Date.now() + ttl * 1000 });
    return fetched;
  }

  private async route(method: string, rawUrl: string, body: Buffer, res: import('node:http').ServerResponse, headers: import('node:http').IncomingHttpHeaders = {}) {
    const url = new URL(rawUrl, 'http://localhost');
    const path = url.pathname;
    let match: RegExpExecArray | null;
    // An Authorization Response above the declared maximum size is refused before it is parsed (RP_WS_SH_Encoding_004).
    if (method === 'POST' && this.options.maxResponseBytes && body.length > this.options.maxResponseBytes) {
      const tx = this.transactions.get(/^\/oid4vp\/([^/]+)\//.exec(path)?.[1] ?? '');
      if (tx?.status === 'pending') Object.assign(tx, { status: 'failure', error: 'the Authorization Response is too large' });
      return sendJson(res, 413, { error: 'invalid_request', error_description: 'the request is too large' });
    }
    if (method === 'POST' && path === '/api/presentations') {
      const { query = 'default_query_pid', flow = 'redirect' } = JSON.parse(body.toString() || '{}');
      if (flow !== 'redirect' && flow !== 'dc-api') return sendJson(res, 400, { error: 'unsupported_flow' });
      if (!(query in this.options.queries)) return sendJson(res, 400, { error: 'unknown_query' });
      return sendJson(res, 201, await this.createTransaction(query, flow));
    }
    if (method === 'GET' && (match = /^\/api\/presentations\/([^/]+)$/.exec(path))) {
      const tx = this.transactions.get(match[1]);
      if (!tx) return sendJson(res, 404, { error: 'not_found' });
      const result: ReferenceRpResult = {
        transactionId: tx.id,
        status: tx.status,
        attributes: tx.attributes,
        ...(tx.flags?.length ? { flags: tx.flags } : {}),
        error: tx.error,
        response: tx.response,
        validations: tx.validations,
      };
      return sendJson(res, 200, result);
    }
    if (method === 'POST' && path === '/api/trust/refresh') {
      return sendJson(res, 200, { lists: await this.refreshTrust() });
    }
    if ((method === 'GET' || method === 'POST') && (match = /^\/oid4vp\/([^/]+)\/request$/.exec(path))) {
      // OpenID4VP 1.0 section 5.10: GET, or POST with wallet_metadata and wallet_nonce (request_uri_method post). The
      // request object of a finished or expired transaction is not served again (ProtocolFlow_004).
      const tx = this.transactions.get(match[1]);
      if (!tx || tx.flow !== 'redirect') return sendJson(res, 404, { error: 'not_found' });
      if (tx.status !== 'pending' || this.expired(tx)) return sendJson(res, 400, { error: 'invalid_request_uri', error_description: 'the transaction is finished' });
      const walletNonce = method === 'POST' ? new URLSearchParams(body.toString()).get('wallet_nonce') : null;
      const jwt = walletNonce ? await this.signWithWalletNonce(tx, walletNonce) : tx.requestJwt;
      return sendText(res, 200, jwt, 'application/oauth-authz-req+jwt');
    }
    if (method === 'POST' && (match = /^\/oid4vp\/([^/]+)\/response$/.exec(path))) {
      return this.handleResponse(match[1], body, res);
    }
    if (method === 'GET' && (match = /^\/dc-api\/([^/]+)$/.exec(path))) {
      const tx = this.transactions.get(match[1]);
      if (!tx || tx.flow !== 'dc-api') return sendJson(res, 404, { error: 'not_found' });
      return sendText(res, 200, dcApiPage(tx), 'text/html; charset=utf-8');
    }
    if (method === 'POST' && (match = /^\/oid4vp\/([^/]+)\/dc-api-response$/.exec(path))) {
      return this.handleDcApiResponse(match[1], body, res);
    }
    if (method === 'GET' && (match = /^\/done\/([^/]+)$/.exec(path))) {
      return this.frontEnd(match[1], url.searchParams.get('response_code'), cookieOf(headers.cookie, USER_SESSION_COOKIE), res);
    }
    return sendJson(res, 404, { error: 'not_found' });
  }

  private async createTransaction(query: DefaultQueryId, flow: Flow) {
    const id = randomUUID();
    const dcApi = flow === 'dc-api';
    const { publicKey, privateKey } = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
    const encryptionJwk = { ...(await exportJWK(publicKey)), kid: `enc-${id}`, use: 'enc', alg: 'ECDH-ES' } as Jwk;
    const accessKey = this.accessKey;
    if (!accessKey) throw new Error('not started');
    const verifier = new Openid4vpVerifier({
      callbacks: {
        hash,
        signJwt: async (signer, { header, payload }) => ({
          jwt: await signCompactJws(header, payload as Record<string, unknown>, accessKey),
          signerJwk: this.options.accessCertificate.privateJwk as Jwk,
        }),
        verifyJwt: () => ({ verified: false }),
        encryptJwe: () => {
          throw new Error('not used');
        },
        decryptJwe: () => ({ decrypted: false }),
      },
    });
    const created = await verifier.createOpenId4vpAuthorizationRequest({
      authorizationRequestPayload: {
        response_type: 'vp_token',
        client_id: this.clientId,
        // Via the DC API the response returns to the page, which posts it here: no response_uri and no state, but the
        // Origin the request may be used from (OpenID4VP 1.0 Appendix A.2).
        ...(dcApi
          ? { response_mode: 'dc_api.jwt' as const, expected_origins: [this.origin] }
          : { response_mode: 'direct_post.jwt' as const, response_uri: `${this.baseUrl}/oid4vp/${id}/response`, state: id }),
        nonce: base64url.encode(randomBytes(32)),
        dcql_query: this.options.queries[query],
        client_metadata: {
          jwks: { keys: [encryptionJwk] },
          encrypted_response_enc_values_supported: ['A128GCM', 'A256GCM'],
          vp_formats_supported: {
            'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] },
            // OpenID4VP 1.0 Appendix B.2.2: COSE algorithm identifiers, ES256.
            mso_mdoc: { issuerauth_alg_values: [-7], deviceauth_alg_values: [-7] },
          },
        },
        verifier_info: [{ format: 'registration_cert', data: this.options.registrationCertificate }],
      },
      jar: {
        ...(dcApi ? {} : { requestUri: `${this.baseUrl}/oid4vp/${id}/request` }),
        jwtSigner: { method: 'x5c', x5c: [this.options.accessCertificate.certificate], alg: 'ES256' },
        expiresInSeconds: 300,
      },
    });
    if (!created.jar) throw new Error('no request object');
    this.transactions.set(id, {
      id,
      query,
      flow,
      status: 'pending',
      createdAt: new Date().toISOString(),
      requestJwt: created.jar.authorizationRequestJwt,
      requestPayload: created.authorizationRequestPayload as Record<string, unknown>,
      encryptionKey: privateKey as CryptoKey,
      encryptionJwk,
      userSession: base64url.encode(randomBytes(32)),
    });
    const tx = this.transactions.get(id) as Transaction;
    // The front end sets the user session as a cookie of the user agent that starts the transaction.
    if (dcApi) return { transactionId: id, dcApiPage: `${this.baseUrl}/dc-api/${id}`, userSession: tx.userSession };
    // The request object can be retrieved with POST and a wallet_nonce as well (ICS RP.P.8).
    const invocation = new URL(created.authorizationRequest);
    invocation.searchParams.set('request_uri_method', 'post');
    return { transactionId: id, uri: invocation.href, userSession: tx.userSession };
  }

  /** Whether the transaction lifetime `T_tx` has passed since the transaction started. */
  private expired(tx: Transaction): boolean {
    return Date.now() - Date.parse(tx.createdAt) > (this.options.transactionLifetimeMs ?? 300_000);
  }

  /** The request object of a transaction with the `wallet_nonce` a wallet posted, signed again (OpenID4VP 1.0 section 5.10.1). */
  private async signWithWalletNonce(tx: Transaction, walletNonce: string): Promise<string> {
    const accessKey = this.accessKey;
    if (!accessKey) throw new Error('not started');
    const [header, payload] = tx.requestJwt.split('.').slice(0, 2).map((part) => base64url.decodeJson<Record<string, unknown>>(part));
    return signCompactJws(header as Record<string, unknown>, { ...payload, wallet_nonce: walletNonce, iat: Math.floor(Date.now() / 1000) }, accessKey);
  }

  /**
   * The front end of a transaction via redirects: the user agent that started it (its cookie) redeems the response
   * code of the `redirect_uri` once and gets the released attributes. A user agent of another session, a response code
   * other than the transaction's, or a second redemption gets nothing (OpenID4VP 1.0 section 13.3, HAIP section 5.1).
   */
  private frontEnd(id: string, responseCode: string | null, userSession: string | undefined, res: import('node:http').ServerResponse) {
    const tx = this.transactions.get(id);
    if (!tx || tx.flow !== 'redirect') return sendJson(res, 404, { error: 'not_found' });
    if (userSession !== tx.userSession) return sendJson(res, 403, { error: 'other_user_session' });
    if (tx.status !== 'success' || !tx.responseCode) return sendJson(res, 400, { error: 'no_result', status: tx.status });
    if (!responseCode || responseCode !== tx.responseCode) return sendJson(res, 400, { error: 'invalid_response_code' });
    if (tx.redeemed) return sendJson(res, 400, { error: 'response_code_used' });
    tx.redeemed = true;
    return sendJson(res, 200, { status: tx.status, attributes: tx.attributes });
  }

  private fail(tx: Transaction, res: import('node:http').ServerResponse, error: string) {
    tx.status = 'failure';
    tx.error = error;
    tx.attributes = undefined;
    return sendJson(res, 400, { error: 'invalid_request', error_description: error });
  }

  private async handleResponse(id: string, body: Buffer, res: import('node:http').ServerResponse) {
    const tx = this.transactions.get(id);
    if (!tx || tx.flow !== 'redirect') return sendJson(res, 404, { error: 'not_found' });
    if (tx.status !== 'pending') return sendJson(res, 400, { error: 'invalid_request', error_description: 'transaction is complete' });
    if (this.expired(tx)) return this.fail(tx, res, 'the transaction lifetime has passed');
    const form = Object.fromEntries(new URLSearchParams(body.toString()));
    // An Authorization Error Response of the wallet (OpenID4VP 1.0 section 8.5) ends the transaction as failed; it was
    // processed successfully, so it is answered with HTTP 200 (section 8.2).
    if (typeof form.error === 'string' && form.response === undefined && form.vp_token === undefined) {
      if (form.state !== tx.requestPayload.state) return this.fail(tx, res, 'the error response carries another state');
      tx.status = 'failure';
      tx.error = `wallet error: ${form.error}`;
      return sendJson(res, 200, {});
    }
    const handover: Oid4vpHandover = { flow: 'redirect', clientId: this.clientId, responseUri: tx.requestPayload.response_uri as string };
    const error = await this.verify(tx, form, { audience: this.clientId, handover, state: tx.requestPayload.state as string });
    if (error) return this.fail(tx, res, error);
    // A fresh response code of 256 bits, which the front end redeems once (OpenID4VP 1.0 section 8.2 and 13.3).
    tx.responseCode = base64url.encode(randomBytes(32));
    return sendJson(res, 200, { redirect_uri: `${this.baseUrl}/done/${tx.id}?response_code=${tx.responseCode}` });
  }

  /**
   * The response its page received through the Digital Credentials API and posted as `{ protocol, data }`. The KB-JWT
   * is addressed to `origin:<origin>` even though the request is signed, and an mdoc's SessionTranscript carries the
   * DC API handover with the Origin (OpenID4VP 1.0 Appendix A.4 and B.2.6.2).
   */
  private async handleDcApiResponse(id: string, body: Buffer, res: import('node:http').ServerResponse) {
    const tx = this.transactions.get(id);
    if (!tx || tx.flow !== 'dc-api') return sendJson(res, 404, { error: 'not_found' });
    if (tx.status !== 'pending') return sendJson(res, 400, { error: 'invalid_request', error_description: 'transaction is complete' });
    let posted: { protocol?: unknown; data?: unknown };
    try {
      posted = JSON.parse(body.toString());
    } catch {
      return this.fail(tx, res, 'the page posted no JSON');
    }
    if (posted.protocol !== DC_API_PROTOCOL) return this.fail(tx, res, `the response is of protocol ${String(posted.protocol)}, not ${DC_API_PROTOCOL}`);
    if (!posted.data || typeof posted.data !== 'object' || Array.isArray(posted.data)) return this.fail(tx, res, 'the response has no data object');
    if (this.expired(tx)) return this.fail(tx, res, 'the transaction lifetime has passed');
    // An error object of the wallet (OpenID4VP 1.0 Appendix A.4) ends the transaction as failed.
    const walletError = (posted.data as { error?: unknown }).error;
    if (typeof walletError === 'string') {
      tx.status = 'failure';
      tx.error = `wallet error: ${walletError}`;
      return sendJson(res, 200, {});
    }
    const error = await this.verify(tx, posted.data as Record<string, unknown>, {
      audience: `origin:${this.origin}`,
      handover: { flow: 'dc-api', origin: this.origin },
    });
    if (error) return this.fail(tx, res, error);
    return sendJson(res, 200, { status: 'success' });
  }

  /**
   * Validates the Authorization Response of a transaction and every presentation in it; returns the reason of the
   * first failure, or records the released attributes.
   */
  private async verify(
    tx: Transaction,
    form: Record<string, unknown>,
    binding: { audience: string; handover: Oid4vpHandover; state?: string },
  ): Promise<string | undefined> {
    const metadata = tx.requestPayload.client_metadata as { encrypted_response_enc_values_supported: string[] };
    const response = await validateAuthorizationResponse(form, {
      keys: [{ kid: tx.encryptionJwk.kid as string, privateKey: tx.encryptionKey }],
      encValues: metadata.encrypted_response_enc_values_supported,
      state: binding.state,
      maxResponseBytes: this.options.maxResponseBytes,
    });
    tx.response = response.checks;
    if (!response.valid || !response.payload) return `${response.failed}: ${response.checks.at(-1)?.detail}`;
    const presentations = response.payload.vp_token as Record<string, unknown>;
    const query = this.options.queries[tx.query];
    // The vp_token as a whole first: known credential query ids, one presentation each unless `multiple`, every
    // required credential query or credential set satisfied, one document per DeviceResponse (UC_Presentation).
    const vpToken = await validateVpToken(presentations, query);
    tx.response = [...response.checks, ...vpToken.checks];
    if (!vpToken.valid) return `${vpToken.failed}: ${vpToken.checks.at(-1)?.detail}`;
    const attributes: Record<string, unknown> = {};
    const validations: (SdJwtVcValidation | MdocValidation)[] = [];
    const disclosed: { id: string; format: string; claims: Record<string, unknown> }[] = [];
    for (const credentialQuery of query.credentials) {
      const entries = presentations[credentialQuery.id] as string[] | undefined;
      // An optional credential query, or one of an option the Wallet did not choose (credential_sets).
      if (!entries) continue;
      const common = {
        trust: this.trust,
        // The root of trust of the credential query's category: TL-PID, TL-QEAA through the LOTL, TL-PUB or the rulebook anchor.
        trustRule: TRUST_RULES[categoryOfCredentialQuery(credentialQuery.id)],
        nonce: tx.requestPayload.nonce as string,
        skewSeconds: this.options.skewSeconds,
        // A PID without reliable revocation status is rejected (catalogue decision 2); for the other categories the
        // reference Relying Party declares RP.R.2 Reject.
        requireStatus: true,
        maxStatusListBytes: this.options.maxStatusListBytes,
        statusListFreshness: this.options.statusListFreshness,
        rejectPastExpiryDate: this.options.rejectPastExpiryDate,
        requireIssuerInCertificate: this.options.requireIssuerInCertificate,
        validStatuses: this.options.validStatuses,
        trustedAuthorities: credentialQuery.trusted_authorities,
        requestedClaims: credentialQuery.claims ?? [],
      };
      for (const entry of entries) {
        const validation =
          credentialQuery.format === 'mso_mdoc'
            ? await validateMdocPresentation(entry, {
                ...common,
                expectedDocType: (credentialQuery.meta?.doctype_value as string | undefined) ?? PID_DOCTYPE,
                handover: binding.handover,
                clientId: this.clientId,
                // OpenID4VP Appendix B.2.6: the thumbprint of the key the response was encrypted to.
                jwkThumbprint: await jwkThumbprint(tx.encryptionJwk as JsonWebKey),
                fetchStatusList: (uri) => this.fetchStatusList(uri, 'application/statuslist+cwt'),
                fetchIdentifierList: (uri) => fetchList(uri, 'application/identifierlist+cwt', this.options.statusTimeoutMs),
              })
            : await validateSdJwtVcPresentation(entry, {
                ...common,
                expectedVct: (credentialQuery.meta?.vct_values as string[] | undefined) ?? [PID_VCT],
                audience: binding.audience,
                kbMaxAgeSeconds: this.options.kbMaxAgeSeconds,
                fetchStatusList: (uri) => this.fetchStatusList(uri, 'application/statuslist+jwt'),
              });
        validations.push(validation);
        tx.validations = validations;
        if (!validation.valid) return `${credentialQuery.id}: ${validation.failed}: ${validation.checks.at(-1)?.detail}`;
        disclosed.push({ id: credentialQuery.id, format: credentialQuery.format, claims: (validation.claims ?? {}) as Record<string, unknown> });
        for (const claim of credentialQuery.claims ?? []) {
          let value: unknown = validation.claims;
          for (const segment of claim.path) value = (value as Record<string, unknown> | undefined)?.[String(segment)];
          if (value === undefined) return `${credentialQuery.id}: requested claim ${claim.path.join('.')} not disclosed`;
          attributes[claim.path.join('.')] = value;
        }
      }
    }
    // Combined presentations: the reference Relying Party binds the credentials by their identifying attributes (ICS
    // RP.P.10 attribute-based, ARF section 6.6.3.10).
    const combined = await validateCombinedBinding(disclosed);
    tx.response = [...tx.response, ...combined.checks];
    if (!combined.valid) return `${combined.failed}: ${combined.checks.at(-1)?.detail}`;
    tx.status = 'success';
    tx.attributes = attributes;
    if (validations.some((v) => v.trustListStale)) tx.flags = ['trust-list-stale'];
    return undefined;
  }
}

/**
 * The reference Relying Party's page for the DC API flow: it passes the signed request to `navigator.credentials.get`
 * and posts the returned `protocol` and `data` to its backend, as a relying-party frontend does.
 */
function dcApiPage(tx: Transaction): string {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Reference Relying Party</title></head>
<body>
<p id="status">Requesting a credential</p>
<script type="module">
const status = document.getElementById('status');
try {
  const credential = await navigator.credentials.get({
    mediation: 'required',
    digital: { requests: [{ protocol: ${JSON.stringify(DC_API_PROTOCOL)}, data: { request: ${JSON.stringify(tx.requestJwt)} } }] },
  });
  const response = await fetch(${JSON.stringify(`/oid4vp/${tx.id}/dc-api-response`)}, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ protocol: credential.protocol, data: credential.data }),
  });
  status.textContent = response.status + ' ' + (await response.text());
} catch (error) {
  status.textContent = 'error: ' + error.name + ': ' + error.message;
}
</script>
</body>
</html>
`;
}

/** The `ttl` of a Status List Token in JWT or CWT format (claim 65534), seconds, or undefined. */
function ttlOf(body: string | Uint8Array): number | undefined {
  try {
    if (typeof body === 'string') {
      const ttl = base64url.decodeJson<{ ttl?: unknown }>(body.trim().split('.')[1] ?? '').ttl;
      return typeof ttl === 'number' && ttl > 0 ? ttl : undefined;
    }
    const payload = readCose(decodeCbor(body)).payload;
    const ttl = payload ? decodeCbor<Map<number, unknown>>(payload).get(65534) : undefined;
    return typeof ttl === 'number' && ttl > 0 ? ttl : undefined;
  } catch {
    return undefined;
  }
}

/** The value of a cookie in a `Cookie` header. */
function cookieOf(header: string | undefined, name: string): string | undefined {
  for (const part of (header ?? '').split(';')) {
    const [key, ...value] = part.trim().split('=');
    if (key === name) return value.join('=');
  }
  return undefined;
}
