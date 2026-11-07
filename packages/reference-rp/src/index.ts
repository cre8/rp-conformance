import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { type CallbackContext, type Jwk, setGlobalConfig } from '@openid4vc/oauth2';
import { Openid4vpVerifier, parseOpenid4vpAuthorizationResponse } from '@openid4vc/openid4vp';
import type { DcqlQuery, DefaultQueryId, KeyedCertificate, RunningServer, ServerOptions } from '@rp-conformance/core';
import { sendJson, sendText, startServer } from '@rp-conformance/core';
import { base64url, PID_VCT, signCompactJws } from '@rp-conformance/forge';
import { type ListSource, type SdJwtVcValidation, TrustStore, validateSdJwtVcPresentation } from '@rp-conformance/validator';
import { compactDecrypt, exportJWK, generateKeyPair, importJWK } from 'jose';

export interface ReferenceRpOptions extends ServerOptions {
  /** Base URL under which the Conformance Wallet reaches the Relying Party. */
  publicBaseUrl?: string;
  trustLists: ListSource[];
  accessCertificate: KeyedCertificate;
  registrationCertificate: string;
  queries: Record<DefaultQueryId, DcqlQuery>;
  /** `T_skew`, seconds. */
  skewSeconds: number;
  /** `T_kb`, seconds. */
  kbMaxAgeSeconds: number;
  /** Lets the OpenID4VP library use `http` URLs, for runs on localhost. */
  allowInsecureUrls?: boolean;
}

export type TransactionStatus = 'pending' | 'success' | 'failure';

interface Transaction {
  id: string;
  query: DefaultQueryId;
  status: TransactionStatus;
  createdAt: string;
  requestJwt: string;
  requestPayload: Record<string, unknown>;
  encryptionKey: CryptoKey;
  encryptionJwk: Jwk;
  attributes?: Record<string, unknown>;
  error?: string;
  validations?: SdJwtVcValidation[];
}

/** The verification result the reference Relying Party exposes for a transaction (its ICS item RP.G.6: API). */
export interface ReferenceRpResult {
  transactionId: string;
  status: TransactionStatus;
  /** Released attributes by claim path joined with `.`. */
  attributes?: Record<string, unknown>;
  error?: string;
  validations?: SdJwtVcValidation[];
}

const hash: CallbackContext['hash'] = (data, alg) => createHash(alg.replace('-', '').toLowerCase()).update(data).digest();

/** `x509_hash` Client Identifier (OpenID4VP 1.0 section 5.9.3): base64url SHA-256 of the DER leaf certificate. */
export function x509HashClientId(certificateBase64Der: string): string {
  return `x509_hash:${base64url.encode(createHash('sha256').update(Buffer.from(certificateBase64Der, 'base64')).digest())}`;
}

/**
 * A minimal Relying Party built on the reference validator (harness design section 7). It signs its request with
 * its access certificate (`x509_hash`), asks for `direct_post.jwt`, verifies the presentation with the reference
 * validator against the trust configuration it loads from the Test Trust Infrastructure, and exposes its
 * verification result through an API.
 */
export class ReferenceRelyingParty {
  private server?: RunningServer;
  private baseUrl = '';
  private readonly transactions = new Map<string, Transaction>();
  readonly trust: TrustStore;
  readonly clientId: string;
  private accessKey?: CryptoKey;

  constructor(private readonly options: ReferenceRpOptions) {
    this.trust = new TrustStore(options.trustLists);
    this.clientId = x509HashClientId(options.accessCertificate.certificate);
  }

  get url(): string {
    return this.baseUrl;
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
      if (flow !== 'redirect') return sendJson(res, 400, { error: 'unsupported_flow' });
      if (!(query in this.options.queries)) return sendJson(res, 400, { error: 'unknown_query' });
      return sendJson(res, 201, await this.createTransaction(query));
    }
    if (method === 'GET' && (match = /^\/api\/presentations\/([^/]+)$/.exec(path))) {
      const tx = this.transactions.get(match[1]);
      if (!tx) return sendJson(res, 404, { error: 'not_found' });
      const result: ReferenceRpResult = {
        transactionId: tx.id,
        status: tx.status,
        attributes: tx.attributes,
        error: tx.error,
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
    if (method === 'GET' && (match = /^\/done\/([^/]+)$/.exec(path))) {
      const tx = this.transactions.get(match[1]);
      return sendText(res, tx ? 200 : 404, `<!doctype html><title>Done</title><p>${tx?.status ?? 'unknown'}</p>`, 'text/html');
    }
    return sendJson(res, 404, { error: 'not_found' });
  }

  private async createTransaction(query: DefaultQueryId) {
    const id = randomUUID();
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
        response_mode: 'direct_post.jwt',
        response_uri: `${this.baseUrl}/oid4vp/${id}/response`,
        nonce: base64url.encode(randomBytes(32)),
        state: id,
        dcql_query: this.options.queries[query],
        client_metadata: {
          jwks: { keys: [encryptionJwk] },
          encrypted_response_enc_values_supported: ['A128GCM', 'A256GCM'],
          vp_formats_supported: { 'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] } },
        },
        verifier_info: [{ format: 'registration_cert', data: this.options.registrationCertificate }],
      },
      jar: {
        requestUri: `${this.baseUrl}/oid4vp/${id}/request`,
        jwtSigner: { method: 'x5c', x5c: [this.options.accessCertificate.certificate], alg: 'ES256' },
        expiresInSeconds: 300,
      },
    });
    if (!created.jar) throw new Error('no request object');
    this.transactions.set(id, {
      id,
      query,
      status: 'pending',
      createdAt: new Date().toISOString(),
      requestJwt: created.jar.authorizationRequestJwt,
      requestPayload: created.authorizationRequestPayload as Record<string, unknown>,
      encryptionKey: privateKey as CryptoKey,
      encryptionJwk,
    });
    return { transactionId: id, uri: created.authorizationRequest };
  }

  private fail(tx: Transaction, res: import('node:http').ServerResponse, error: string) {
    tx.status = 'failure';
    tx.error = error;
    tx.attributes = undefined;
    return sendJson(res, 400, { error: 'invalid_request', error_description: error });
  }

  private async handleResponse(id: string, body: Buffer, res: import('node:http').ServerResponse) {
    const tx = this.transactions.get(id);
    if (!tx) return sendJson(res, 404, { error: 'not_found' });
    if (tx.status !== 'pending') return sendJson(res, 400, { error: 'invalid_request', error_description: 'transaction is complete' });
    const params = Object.fromEntries(new URLSearchParams(body.toString()));
    if (!params.response) return this.fail(tx, res, 'the response is not encrypted (direct_post.jwt requires response)');
    let parsed: Awaited<ReturnType<typeof parseOpenid4vpAuthorizationResponse>>;
    try {
      parsed = await parseOpenid4vpAuthorizationResponse({
        authorizationResponse: params,
        authorizationRequestPayload: tx.requestPayload as never,
        callbacks: {
          verifyJwt: () => ({ verified: false }),
          decryptJwe: async (jwe) => {
            try {
              const { plaintext, protectedHeader } = await compactDecrypt(jwe, tx.encryptionKey, {
                keyManagementAlgorithms: ['ECDH-ES'],
                contentEncryptionAlgorithms: ['A128GCM', 'A256GCM'],
              });
              if (protectedHeader.kid !== undefined && protectedHeader.kid !== tx.encryptionJwk.kid) return { decrypted: false };
              return { decrypted: true, decryptionJwk: tx.encryptionJwk, payload: new TextDecoder().decode(plaintext) };
            } catch {
              return { decrypted: false };
            }
          },
        },
      });
    } catch (error) {
      return this.fail(tx, res, `invalid authorization response: ${(error as Error).message}`);
    }
    if (parsed.type !== 'dcql') return this.fail(tx, res, 'expected a DCQL vp_token');
    const query = this.options.queries[tx.query];
    const attributes: Record<string, unknown> = {};
    const validations: SdJwtVcValidation[] = [];
    for (const credentialQuery of query.credentials) {
      const entries = parsed.dcql.presentations[credentialQuery.id];
      if (!entries || entries.length !== 1 || typeof entries[0] !== 'string') {
        return this.fail(tx, res, `expected one presentation for ${credentialQuery.id}`);
      }
      const validation = await validateSdJwtVcPresentation(entries[0], {
        trust: this.trust,
        issuerList: 'TL-PID',
        expectedVct: (credentialQuery.meta?.vct_values as string[] | undefined) ?? [PID_VCT],
        nonce: tx.requestPayload.nonce as string,
        audience: this.clientId,
        skewSeconds: this.options.skewSeconds,
        kbMaxAgeSeconds: this.options.kbMaxAgeSeconds,
        requireStatus: true,
        fetchStatusList: async (uri) => {
          const response = await fetch(uri, { headers: { accept: 'application/statuslist+jwt' }, signal: AbortSignal.timeout(5000) });
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          return response.text();
        },
      });
      validations.push(validation);
      tx.validations = validations;
      if (!validation.valid) return this.fail(tx, res, `${credentialQuery.id}: ${validation.failed}: ${validation.checks.at(-1)?.detail}`);
      for (const claim of credentialQuery.claims ?? []) {
        let value: unknown = validation.claims;
        for (const segment of claim.path) value = (value as Record<string, unknown> | undefined)?.[String(segment)];
        if (value === undefined) return this.fail(tx, res, `${credentialQuery.id}: requested claim ${claim.path.join('.')} not disclosed`);
        attributes[claim.path.join('.')] = value;
      }
    }
    tx.status = 'success';
    tx.attributes = attributes;
    return sendJson(res, 200, { redirect_uri: `${this.baseUrl}/done/${tx.id}` });
  }
}
