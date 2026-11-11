// The Conformance Wallet. It started from EUDIPLO's headless E2E wallet (apps/client/e2e/support/wallet.ts), which
// answers signed OpenID4VP requests with direct_post.jwt, and adds what a conformance run needs: trust in the
// request signer per TL-AC, findings on the request, and evidence of every exchange.
import { createHash, X509Certificate } from 'node:crypto';
import { type CallbackContext, type Jwk, setGlobalConfig } from '@openid4vc/oauth2';
import { Openid4vpClient } from '@openid4vc/openid4vp';
import type { CredentialFormat, FaultId } from '@rp-conformance/core';
import {
  base64url,
  buildAuthorizationResponse,
  buildDcApiResponse,
  type EcKeyPair,
  encodeDeviceResponse,
  generateEcKeyPair,
  jwkThumbprint,
  type Oid4vpHandover,
  presentMdoc,
  presentSdJwtVc,
  requestedElements,
  verifyEs256,
} from '@rp-conformance/forge';
import { validatePath } from '@rp-conformance/validator';
import { type Certificate, parseCertificate } from '@owf/x509';
import type { JWK } from 'jose';

/** A deviation of the Relying Party's request from OpenID4VP 1.0 or HAIP 1.0 (harness design section 4.5). */
export interface WalletFinding {
  severity: 'error' | 'warning';
  code: string;
  message: string;
}

export interface HttpExchange {
  method: string;
  url: string;
  status?: number;
  contentType?: string | null;
  body?: string;
  error?: string;
}

/** Everything the wallet saw and sent for one presentation, kept as evidence. */
export interface PresentationEvidence {
  /** The invocation URI (redirects), or the URL of the Relying Party's page (DC API). */
  invocationUri: string;
  /** Via the DC API: the page's Origin, the requests the page passed, and the protocol the wallet answered. */
  dcApi?: { origin: string; requests: DcApiRequest[]; protocol?: string };
  requestFetch?: HttpExchange;
  request?: { header: Record<string, unknown>; payload: Record<string, unknown> };
  findings: WalletFinding[];
  /** The encryption key from the request's `client_metadata`. */
  encryptionKey?: JWK;
  presentation?: string;
  /** The `response` parameter, when there is one. */
  responseJwe?: string;
  /** Every form parameter posted to `response_uri`. */
  responseForm?: Record<string, string>;
  /** Via the DC API: the `data` object the wallet returned to the page. */
  responseData?: Record<string, unknown>;
  response?: HttpExchange;
  redirect?: HttpExchange;
  /** Set when the wallet could not complete the flow. */
  error?: string;
}

export interface ConformanceWalletOptions {
  /** Anchors of `TL-AC`: the wallet trusts a request signer only under one of them. */
  accessCertificateAnchors: (Certificate | string)[];
  /** Accept `http` URLs (localhost runs); each one is still a finding. */
  allowInsecureUrls?: boolean;
  /** Follow `redirect_uri` after the response (default true). */
  followRedirect?: boolean;
}

const hash: CallbackContext['hash'] = (data, alg) => createHash(alg.replace('-', '').toLowerCase()).update(data).digest();

const SUPPORTED_ENC = ['A128GCM', 'A256GCM'];

/** A credential the Conformance Wallet holds: an SD-JWT VC (compact, without KB-JWT) or an mdoc's `IssuerSigned` (CBOR). */
export type HeldCredential = { format: 'dc+sd-jwt'; value: string } | { format: 'mso_mdoc'; value: Uint8Array };

/** How the Conformance Wallet answers: the content encryption to use and the fault of the response, if any. */
export interface ResponseOptions {
  enc?: string;
  fault?: FaultId;
  /** For `response.other-transaction-key`: the encryption key recorded for another transaction. */
  otherTransactionKey?: JWK;
}

type Finding = (severity: WalletFinding['severity'], code: string, message: string) => void;

/** One entry of `digital.requests` that the Relying Party's page passed to `navigator.credentials.get`. */
export interface DcApiRequest {
  protocol: string;
  data: unknown;
}

/** A call of `navigator.credentials.get` that the DC API shim forwards: the page, its Origin and its requests. */
export interface DcApiCall {
  /** The Origin of the calling page as the browser serialises it (`https://rp.example`, no trailing slash). */
  origin: string;
  pageUrl: string;
  requests: DcApiRequest[];
}

/** What the wallet returns to the page: the resolved `DigitalCredential`'s `protocol` and `data`. */
export interface DcApiAnswer {
  protocol: string;
  data: Record<string, unknown>;
}

/** The OpenID4VP protocol identifiers of the DC API (OpenID4VP 1.0 Appendix A.1), all of which HAIP 1.0 section 5.2 requires of a Wallet. */
export const DC_API_PROTOCOLS = ['openid4vp-v1-signed', 'openid4vp-v1-multisigned', 'openid4vp-v1-unsigned'] as const;

type RequestBinding = { audience: string; handover: Oid4vpHandover; state?: string };

const decodeSegment = (segment: unknown) => base64url.decodeJson<Record<string, unknown>>(String(segment ?? ''));

export class ConformanceWallet {
  private constructor(
    readonly holderKey: EcKeyPair,
    private readonly options: ConformanceWalletOptions,
    private readonly anchors: Certificate[],
  ) {}

  static async create(options: ConformanceWalletOptions): Promise<ConformanceWallet> {
    if (options.allowInsecureUrls) setGlobalConfig({ allowInsecureUrls: true });
    const anchors = options.accessCertificateAnchors.map((a) => (typeof a === 'string' ? parseCertificate(a) : a));
    return new ConformanceWallet(await generateEcKeyPair(), options, anchors);
  }

  /**
   * Resolves the request behind `invocationUri` and records its encryption key, without answering it (SessionEncryption
   * transaction T1).
   */
  async start(invocationUri: string): Promise<PresentationEvidence> {
    const evidence: PresentationEvidence = { invocationUri, findings: [] };
    try {
      await this.resolve(invocationUri, evidence);
    } catch (error) {
      evidence.error = (error as Error).message;
    }
    return evidence;
  }

  /**
   * Answers the request behind `invocationUri` (redirect flow): resolves `request_uri`, verifies the signed request
   * and its `x509_hash` Client Identifier against `TL-AC`, presents the credential bound to the request (an SD-JWT VC
   * with a KB-JWT, or an mdoc DeviceResponse with a device signature over the SessionTranscript of OpenID4VP
   * Appendix B.2.6.1), encrypts the response (`direct_post.jwt`), or applies the step's response fault, posts it to
   * `response_uri` and follows `redirect_uri`.
   */
  async present(invocationUri: string, credential: HeldCredential, options: ResponseOptions = {}): Promise<PresentationEvidence> {
    const evidence: PresentationEvidence = { invocationUri, findings: [] };
    try {
      const request = await this.resolve(invocationUri, evidence);
      const binding: RequestBinding = {
        audience: request.client_id as string,
        handover: { flow: 'redirect', clientId: request.client_id as string, responseUri: request.response_uri as string },
        state: request.state as string | undefined,
      };
      const input = await this.responseInput(request, credential, binding, evidence, options);
      const form = await buildAuthorizationResponse(input, options.fault);
      evidence.responseForm = form;
      evidence.responseJwe = form.response;

      const responseUri = request.response_uri as string;
      const exchange: HttpExchange = { method: 'POST', url: responseUri };
      evidence.response = exchange;
      const response = await fetch(responseUri, { method: 'POST', body: new URLSearchParams(form) });
      exchange.status = response.status;
      exchange.contentType = response.headers.get('content-type');
      exchange.body = await response.text();

      if (response.ok && this.options.followRedirect !== false) {
        let redirectUri: unknown;
        try {
          redirectUri = (JSON.parse(exchange.body) as { redirect_uri?: unknown }).redirect_uri;
        } catch {
          // OpenID4VP 1.0 section 8.2: the body is JSON; a missing redirect_uri is allowed.
        }
        if (typeof redirectUri === 'string') {
          const redirect: HttpExchange = { method: 'GET', url: redirectUri };
          evidence.redirect = redirect;
          try {
            const followed = await fetch(redirectUri, { redirect: 'manual' });
            redirect.status = followed.status;
            redirect.contentType = followed.headers.get('content-type');
          } catch (error) {
            redirect.error = (error as Error).message;
          }
        }
      }
    } catch (error) {
      evidence.error = (error as Error).message;
    }
    return evidence;
  }

  /**
   * Resolves a request the Relying Party's page passed to the Digital Credentials API and records its encryption key,
   * without answering it (SessionEncryption transaction T1).
   */
  async startDcApi(call: DcApiCall): Promise<PresentationEvidence> {
    const evidence: PresentationEvidence = { invocationUri: call.pageUrl, dcApi: { origin: call.origin, requests: call.requests }, findings: [] };
    try {
      await this.resolveDcApi(call, evidence);
    } catch (error) {
      evidence.error = (error as Error).message;
    }
    return evidence;
  }

  /**
   * Answers a request the Relying Party's page passed to the Digital Credentials API (OpenID4VP 1.0 Appendix A):
   * verifies a signed or multi-signed request against `TL-AC` and its `expected_origins` against the page's Origin,
   * presents the credential bound to the request with the audience `origin:<origin>` (A.4, for signed requests too)
   * or, for an mdoc, the `OpenID4VPDCAPIHandover` (B.2.6.2), and returns the `data` object of response mode
   * `dc_api.jwt`, or the step's response fault. `answer` is unset when the wallet could not answer.
   */
  async presentDcApi(
    call: DcApiCall,
    credential: HeldCredential,
    options: ResponseOptions = {},
  ): Promise<{ evidence: PresentationEvidence; answer?: DcApiAnswer }> {
    const evidence: PresentationEvidence = { invocationUri: call.pageUrl, dcApi: { origin: call.origin, requests: call.requests }, findings: [] };
    try {
      const { request, protocol } = await this.resolveDcApi(call, evidence);
      const binding: RequestBinding = { audience: `origin:${call.origin}`, handover: { flow: 'dc-api', origin: call.origin } };
      const input = await this.responseInput(request, credential, binding, evidence, options);
      const data = await buildDcApiResponse(input, options.fault);
      evidence.responseData = data;
      if (typeof data.response === 'string') evidence.responseJwe = data.response;
      return { evidence, answer: { protocol, data } };
    } catch (error) {
      evidence.error = (error as Error).message;
      return { evidence };
    }
  }

  /** Builds the presentation bound to the request and the payload of the response, before encryption. */
  private async responseInput(
    request: Record<string, unknown>,
    credential: HeldCredential,
    binding: RequestBinding,
    evidence: PresentationEvidence,
    options: ResponseOptions,
  ) {
    const query = request.dcql_query as { credentials: { id: string; format: CredentialFormat; claims?: { path: (string | number | null)[] }[] }[] };
    const credentialQuery = query.credentials.find((c) => c.format === credential.format);
    if (!credentialQuery) throw new Error(`the request asks for no credential in ${credential.format} format`);
    if (!evidence.encryptionKey) throw new Error('client_metadata has no encryption key');
    if (credential.format === 'mso_mdoc') {
      const deviceResponse = await presentMdoc(credential.value, {
        holderPrivateKey: this.holderKey.privateKey,
        handover: binding.handover,
        nonce: request.nonce as string,
        jwkThumbprint: await jwkThumbprint(evidence.encryptionKey as JsonWebKey),
        elements: requestedElements(credentialQuery.claims),
      });
      evidence.presentation = encodeDeviceResponse(deviceResponse);
    } else {
      evidence.presentation = await presentSdJwtVc(credential.value, {
        holderPrivateKey: this.holderKey.privateKey,
        disclose: [...new Set((credentialQuery.claims ?? []).map((claim) => String(claim.path[0])))],
        audience: binding.audience,
        nonce: request.nonce as string,
      });
    }
    const metadata = request.client_metadata as { encrypted_response_enc_values_supported?: string[] };
    const enc = options.enc ?? metadata.encrypted_response_enc_values_supported?.find((e) => SUPPORTED_ENC.includes(e)) ?? 'A128GCM';
    const payload = { vp_token: { [credentialQuery.id]: [evidence.presentation] }, ...(binding.state ? { state: binding.state } : {}) };
    return { payload, recipient: evidence.encryptionKey, enc, walletKey: this.holderKey, otherTransactionKey: options.otherTransactionKey };
  }

  /** An OpenID4VP client whose `verifyJwt` trusts a request signer only under a `TL-AC` anchor, recording the request. */
  private client(evidence: PresentationEvidence, finding: Finding): Openid4vpClient {
    const fetchWithEvidence: typeof fetch = async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      const exchange: HttpExchange = { method: init?.method ?? 'GET', url };
      evidence.requestFetch = exchange;
      const response = await fetch(input, init);
      exchange.status = response.status;
      exchange.contentType = response.headers.get('content-type');
      exchange.body = await response.clone().text();
      return response;
    };
    return new Openid4vpClient({
      callbacks: {
        hash,
        fetch: fetchWithEvidence,
        verifyJwt: async (signer, { header, payload, compact }) => {
          evidence.request = { header: header as Record<string, unknown>, payload: payload as Record<string, unknown> };
          if (signer.method !== 'x5c') {
            finding('error', 'request-signer', `request signed with method ${signer.method}, expected x5c`);
            return { verified: false };
          }
          const [h, p, s] = compact.split('.');
          const jwk = await this.verifySigner(signer.x5c, `${h}.${p}`, base64url.decode(s ?? ''), finding);
          return jwk ? { verified: true, signerJwk: jwk as Jwk } : { verified: false };
        },
        getX509CertificateMetadata: (certificate) => {
          const altNames = new X509Certificate(Buffer.from(certificate, 'base64')).subjectAltName ?? '';
          const names = altNames.split(',').map((name) => name.trim());
          return {
            sanDnsNames: names.filter((n) => n.startsWith('DNS:')).map((n) => n.slice(4)),
            sanUriNames: names.filter((n) => n.startsWith('URI:')).map((n) => n.slice(4)),
          };
        },
        signJwt: () => {
          throw new Error('not used');
        },
        encryptJwe: () => {
          throw new Error('not used');
        },
        decryptJwe: () => ({ decrypted: false }),
      },
    });
  }

  /** Verifies an ES256 request signature by the leaf of `x5c`, which must chain to a `TL-AC` anchor; returns its key. */
  private async verifySigner(x5c: string[], signingInput: string, signature: Uint8Array, finding: Finding): Promise<JsonWebKey | undefined> {
    const path = await validatePath(x5c, this.anchors);
    if (!path.ok) finding('error', 'request-signer-trust', `request signer is not under a TL-AC anchor: ${path.reason}`);
    const jwk = path.ok ? path.leaf.publicKey.jwk : parseCertificate(x5c[0]).publicKey.jwk;
    const verified = jwk ? await verifyEs256(jwk, signingInput, signature) : false;
    if (!verified) finding('error', 'request-signature', 'request signature does not verify');
    return verified && path.ok ? jwk : undefined;
  }

  /** Fetches and verifies the request of the redirect flow; refuses it on an error finding. */
  private async resolve(invocationUri: string, evidence: PresentationEvidence): Promise<Record<string, unknown>> {
    const finding: Finding = (severity, code, message) => evidence.findings.push({ severity, code, message });
    const client = this.client(evidence, finding);
    const parsed = client.parseOpenid4vpAuthorizationRequest({ authorizationRequest: invocationUri });
    const { authorizationRequestPayload: request, client: resolvedClient } = await client.resolveOpenId4vpAuthorizationRequest({
      authorizationRequestPayload: parsed.params as never,
      responseMode: { type: 'direct_post' },
    });
    this.checkRequest(request as Record<string, unknown>, evidence, finding, resolvedClient);
    return this.accept(request as Record<string, unknown>, evidence);
  }

  /**
   * Resolves the first request of a DC API call whose protocol the wallet supports (OpenID4VP 1.0 Appendix A.3): a
   * signed request object in `data.request` (verified by the library against `expected_origins`), a multi-signed one
   * (JWS JSON serialization, one signature per Client Identifier, `client_id` in its protected header), or the
   * parameters of an unsigned request. Refuses it on an error finding.
   */
  private async resolveDcApi(call: DcApiCall, evidence: PresentationEvidence): Promise<{ request: Record<string, unknown>; protocol: string }> {
    const finding: Finding = (severity, code, message) => evidence.findings.push({ severity, code, message });
    const chosen = call.requests.find((r) => (DC_API_PROTOCOLS as readonly string[]).includes(r.protocol));
    if (!chosen) throw new Error(`no request with a protocol the wallet supports (${call.requests.map((r) => r.protocol).join(', ') || 'no requests'})`);
    if (evidence.dcApi) evidence.dcApi.protocol = chosen.protocol;
    const data = (chosen.data ?? {}) as Record<string, unknown>;
    let request: Record<string, unknown>;
    let resolvedClient: { prefix?: string } | undefined;
    if (chosen.protocol === 'openid4vp-v1-multisigned') {
      request = await this.resolveMultiSigned(data, evidence, finding);
    } else {
      if (chosen.protocol === 'openid4vp-v1-signed' && typeof data.request !== 'string') {
        throw new Error('a request of protocol openid4vp-v1-signed carries its request object as a string in data.request');
      }
      if (chosen.protocol === 'openid4vp-v1-unsigned') {
        if (data.request !== undefined) finding('error', 'protocol', 'a request of protocol openid4vp-v1-unsigned carries a request object');
        evidence.request = { header: {}, payload: data };
      }
      const client = this.client(evidence, finding);
      const parsed = client.parseOpenid4vpAuthorizationRequest({ authorizationRequest: data });
      const resolved = await client.resolveOpenId4vpAuthorizationRequest({
        authorizationRequestPayload: parsed.params as never,
        responseMode: { type: 'dc_api', expectedOrigin: call.origin },
      });
      request = resolved.authorizationRequestPayload as Record<string, unknown>;
      resolvedClient = resolved.client;
    }
    this.checkRequest(request, evidence, finding, resolvedClient, { origin: call.origin, protocol: chosen.protocol });
    return { request: this.accept(request, evidence), protocol: chosen.protocol };
  }

  /** A multi-signed request (OpenID4VP 1.0 Appendix A.3.2.2): uses the first signature by a signer under `TL-AC`. */
  private async resolveMultiSigned(data: Record<string, unknown>, evidence: PresentationEvidence, finding: Finding): Promise<Record<string, unknown>> {
    const jws = (data.request && typeof data.request === 'object' ? data.request : data) as {
      payload?: unknown;
      signatures?: { protected?: string; signature?: string }[];
    };
    if (typeof jws.payload !== 'string' || !Array.isArray(jws.signatures) || jws.signatures.length === 0) {
      throw new Error('a request of protocol openid4vp-v1-multisigned is a JWS in general JSON serialization with payload and signatures');
    }
    const payload = decodeSegment(jws.payload);
    const rejected: WalletFinding[] = [];
    for (const entry of jws.signatures) {
      const header = decodeSegment(entry.protected);
      if (header.alg !== 'ES256' || !Array.isArray(header.x5c)) continue;
      const jwk = await this.verifySigner(header.x5c as string[], `${entry.protected}.${jws.payload}`, base64url.decode(entry.signature ?? ''), (severity, code, message) =>
        rejected.push({ severity, code, message }),
      );
      if (!jwk) continue;
      evidence.request = { header, payload };
      // client_id, verifier_info and prefix-specific parameters are in the protected header of their signature.
      return { ...payload, client_id: header.client_id, ...(header.verifier_info ? { verifier_info: header.verifier_info } : {}) };
    }
    evidence.request = { header: decodeSegment(jws.signatures[0]?.protected), payload };
    for (const f of rejected) finding(f.severity, f.code, f.message);
    finding('error', 'request-signer-trust', 'no signature of the multi-signed request verifies with a signer under a TL-AC anchor');
    throw new Error('request refused: no trusted signature');
  }

  /** Records the request's encryption key and refuses the request on an error finding. */
  private accept(request: Record<string, unknown>, evidence: PresentationEvidence): Record<string, unknown> {
    const metadata = request.client_metadata as { jwks?: { keys: JWK[] } } | undefined;
    evidence.encryptionKey = metadata?.jwks?.keys.find((k) => k.use === undefined || k.use === 'enc');
    if (evidence.findings.some((f) => f.severity === 'error')) {
      throw new Error(`request refused: ${evidence.findings.filter((f) => f.severity === 'error').map((f) => f.code).join(', ')}`);
    }
    return request;
  }

  /** Checks the request against OpenID4VP 1.0 and HAIP 1.0: section 5 for redirects, Appendix A and HAIP 5.2 for the DC API. */
  private checkRequest(
    request: Record<string, unknown>,
    evidence: PresentationEvidence,
    finding: Finding,
    client: { prefix?: string } | undefined,
    dcApi?: { origin: string; protocol: string },
  ) {
    const header = evidence.request?.header ?? {};
    const signed = dcApi?.protocol !== 'openid4vp-v1-unsigned';
    if (signed) {
      if (header.typ !== 'oauth-authz-req+jwt') finding('warning', 'request-typ', `request object typ is ${String(header.typ)}, expected oauth-authz-req+jwt`);
      const clientId = String(request.client_id ?? '');
      if (!clientId.startsWith('x509_hash:')) finding('warning', 'client-id-prefix', `client_id ${clientId} does not use the x509_hash prefix (HAIP 1.0)`);
      if (client?.prefix && client.prefix !== 'x509_hash') finding('warning', 'client-id-prefix', `client identifier prefix ${client.prefix}`);
    }
    if (dcApi) {
      if (request.response_mode !== 'dc_api.jwt') finding('error', 'response-mode', `response_mode ${String(request.response_mode)}, expected dc_api.jwt (HAIP 1.0 section 5.2)`);
      const origins = request.expected_origins;
      if (signed && (!Array.isArray(origins) || !origins.includes(dcApi.origin))) {
        finding('error', 'expected-origins', `expected_origins ${JSON.stringify(origins)} does not name the page's Origin ${dcApi.origin}`);
      }
      if (!signed) finding('warning', 'unsigned-request', 'the request is unsigned, so the Relying Party is not authenticated');
    } else {
      if (request.response_mode !== 'direct_post.jwt') finding('error', 'response-mode', `response_mode ${String(request.response_mode)}, expected direct_post.jwt`);
      const value = request.response_uri;
      if (typeof value !== 'string') finding('error', 'response_uri', 'response_uri is missing');
      else if (!value.startsWith('https://')) finding(this.options.allowInsecureUrls ? 'warning' : 'error', 'response_uri-not-https', `response_uri ${value} is not https`);
    }
    if (!request.dcql_query) finding('error', 'dcql-query', 'the request has no dcql_query');
    const verifierInfo = request.verifier_info as { format?: string }[] | undefined;
    if (!verifierInfo?.some((info) => info.format === 'registration_cert')) {
      finding('warning', 'registration-certificate', 'the request carries no registration certificate in verifier_info');
    }
  }
}

