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
import { categoryOfQuery, sendJson, sendText, startServer } from '@rp-conformance/core';
import { base64url, jwkThumbprint, type Oid4vpHandover, PID_DOCTYPE, PID_VCT, signCompactJws } from '@rp-conformance/forge';
import type { CheckResult } from '@rp-conformance/core';
import {
  type FetchedStatusList,
  type ListSource,
  type MdocValidation,
  type SdJwtVcValidation,
  TRUST_RULES,
  TrustStore,
  validateAuthorizationResponse,
  validateMdocPresentation,
  validateSdJwtVcPresentation,
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
  error?: string;
  response?: CheckResult[];
  validations?: (SdJwtVcValidation | MdocValidation)[];
}

/** The verification result the reference Relying Party exposes for a transaction (its ICS item RP.G.6: API). */
export interface ReferenceRpResult {
  transactionId: string;
  status: TransactionStatus;
  /** Released attributes by claim path joined with `.`. */
  attributes?: Record<string, unknown>;
  error?: string;
  /** The checks of the Authorization Response. */
  response?: CheckResult[];
  validations?: (SdJwtVcValidation | MdocValidation)[];
}

const hash: CallbackContext['hash'] = (data, alg) => createHash(alg.replace('-', '').toLowerCase()).update(data).digest();

/** Fetches a status list or identifier list: text for a JWT, bytes for a CWT. */
async function fetchList(uri: string, accept: string): Promise<FetchedStatusList> {
  const fetched = await fetch(uri, { headers: { accept }, signal: AbortSignal.timeout(5000) });
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

  constructor(private readonly options: ReferenceRpOptions) {
    this.trust = new TrustStore({
      lotes: options.trustLists,
      listOfTrustedLists: options.listOfTrustedLists,
      rulebooks: options.rulebooks,
    });
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
    this.server = await startServer(this.options, (req, res, body) => this.route(req.method ?? 'GET', req.url ?? '/', body, res));
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

  private async route(method: string, rawUrl: string, body: Buffer, res: import('node:http').ServerResponse) {
    const path = new URL(rawUrl, 'http://localhost').pathname;
    let match: RegExpExecArray | null;
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
        error: tx.error,
        response: tx.response,
        validations: tx.validations,
      };
      return sendJson(res, 200, result);
    }
    if (method === 'POST' && path === '/api/trust/refresh') {
      return sendJson(res, 200, { lists: await this.refreshTrust() });
    }
    if (method === 'GET' && (match = /^\/oid4vp\/([^/]+)\/request$/.exec(path))) {
      const tx = this.transactions.get(match[1]);
      if (!tx) return sendJson(res, 404, { error: 'not_found' });
      return sendText(res, 200, tx.requestJwt, 'application/oauth-authz-req+jwt');
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
      const tx = this.transactions.get(match[1]);
      return sendText(res, tx ? 200 : 404, `<!doctype html><title>Done</title><p>${tx?.status ?? 'unknown'}</p>`, 'text/html');
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
    });
    return dcApi ? { transactionId: id, dcApiPage: `${this.baseUrl}/dc-api/${id}` } : { transactionId: id, uri: created.authorizationRequest };
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
    const form = Object.fromEntries(new URLSearchParams(body.toString()));
    const handover: Oid4vpHandover = { flow: 'redirect', clientId: this.clientId, responseUri: tx.requestPayload.response_uri as string };
    const error = await this.verify(tx, form, { audience: this.clientId, handover, state: tx.requestPayload.state as string });
    if (error) return this.fail(tx, res, error);
    return sendJson(res, 200, { redirect_uri: `${this.baseUrl}/done/${tx.id}` });
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
    });
    tx.response = response.checks;
    if (!response.valid || !response.payload) return `${response.failed}: ${response.checks.at(-1)?.detail}`;
    const presentations = response.payload.vp_token as Record<string, unknown>;
    const query = this.options.queries[tx.query];
    const attributes: Record<string, unknown> = {};
    const validations: (SdJwtVcValidation | MdocValidation)[] = [];
    for (const credentialQuery of query.credentials) {
      const entries = presentations[credentialQuery.id];
      if (!Array.isArray(entries) || entries.length !== 1 || typeof entries[0] !== 'string') {
        return `expected one presentation for ${credentialQuery.id}`;
      }
      const common = {
        trust: this.trust,
        // The root of trust of the query's category: TL-PID, TL-QEAA through the LOTL, TL-PUB or the rulebook anchor.
        trustRule: TRUST_RULES[categoryOfQuery(tx.query)],
        nonce: tx.requestPayload.nonce as string,
        skewSeconds: this.options.skewSeconds,
        // A PID without reliable revocation status is rejected (catalogue decision 2); for the other categories the
        // reference Relying Party declares RP.R.2 Reject.
        requireStatus: true,
        maxStatusListBytes: this.options.maxStatusListBytes,
        validStatuses: this.options.validStatuses,
        trustedAuthorities: credentialQuery.trusted_authorities,
      };
      const validation =
        credentialQuery.format === 'mso_mdoc'
          ? await validateMdocPresentation(entries[0], {
              ...common,
              expectedDocType: (credentialQuery.meta?.doctype_value as string | undefined) ?? PID_DOCTYPE,
              handover: binding.handover,
              // OpenID4VP Appendix B.2.6: the thumbprint of the key the response was encrypted to.
              jwkThumbprint: await jwkThumbprint(tx.encryptionJwk as JsonWebKey),
              fetchStatusList: (uri) => fetchList(uri, 'application/statuslist+cwt'),
              fetchIdentifierList: (uri) => fetchList(uri, 'application/identifierlist+cwt'),
            })
          : await validateSdJwtVcPresentation(entries[0], {
              ...common,
              expectedVct: (credentialQuery.meta?.vct_values as string[] | undefined) ?? [PID_VCT],
              audience: binding.audience,
              kbMaxAgeSeconds: this.options.kbMaxAgeSeconds,
              fetchStatusList: (uri) => fetchList(uri, 'application/statuslist+jwt'),
            });
      validations.push(validation);
      tx.validations = validations;
      if (!validation.valid) return `${credentialQuery.id}: ${validation.failed}: ${validation.checks.at(-1)?.detail}`;
      for (const claim of credentialQuery.claims ?? []) {
        let value: unknown = validation.claims;
        for (const segment of claim.path) value = (value as Record<string, unknown> | undefined)?.[String(segment)];
        if (value === undefined) return `${credentialQuery.id}: requested claim ${claim.path.join('.')} not disclosed`;
        attributes[claim.path.join('.')] = value;
      }
    }
    tx.status = 'success';
    tx.attributes = attributes;
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
