// The Conformance Wallet. It started from EUDIPLO's headless E2E wallet (apps/client/e2e/support/wallet.ts), which
// answers signed OpenID4VP requests with direct_post.jwt, and adds what a conformance run needs: trust in the
// request signer per TL-AC, findings on the request, and evidence of every exchange.
import { createHash, X509Certificate } from 'node:crypto';
import { type CallbackContext, type Jwk, setGlobalConfig } from '@openid4vc/oauth2';
import { Openid4vpClient } from '@openid4vc/openid4vp';
import { base64url, type EcKeyPair, generateEcKeyPair, presentSdJwtVc, verifyEs256 } from '@rp-conformance/forge';
import { validatePath } from '@rp-conformance/validator';
import { type Certificate, parseCertificate } from '@owf/x509';
import { CompactEncrypt, importJWK, type JWK } from 'jose';

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
  invocationUri: string;
  requestFetch?: HttpExchange;
  request?: { header: Record<string, unknown>; payload: Record<string, unknown> };
  findings: WalletFinding[];
  presentation?: string;
  responseJwe?: string;
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
   * Answers the request behind `invocationUri` (redirect flow): resolves `request_uri`, verifies the signed request
   * and its `x509_hash` Client Identifier against `TL-AC`, presents the credential with a KB-JWT bound to the request,
   * encrypts the response (`direct_post.jwt`), posts it to `response_uri` and follows `redirect_uri`.
   */
  async present(invocationUri: string, credential: string): Promise<PresentationEvidence> {
    const evidence: PresentationEvidence = { invocationUri, findings: [] };
    const finding = (severity: WalletFinding['severity'], code: string, message: string) => evidence.findings.push({ severity, code, message });
    try {
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
      const client = new Openid4vpClient({
        callbacks: {
          hash,
          fetch: fetchWithEvidence,
          verifyJwt: async (signer, { header, payload, compact }) => {
            evidence.request = { header: header as Record<string, unknown>, payload: payload as Record<string, unknown> };
            if (signer.method !== 'x5c') {
              finding('error', 'request-signer', `request signed with method ${signer.method}, expected x5c`);
              return { verified: false };
            }
            const path = await validatePath(signer.x5c, this.anchors);
            if (!path.ok) finding('error', 'request-signer-trust', `request signer is not under a TL-AC anchor: ${path.reason}`);
            const jwk = path.ok ? path.leaf.publicKey.jwk : parseCertificate(signer.x5c[0]).publicKey.jwk;
            const [h, p, s] = compact.split('.');
            const verified = jwk ? await verifyEs256(jwk, `${h}.${p}`, base64url.decode(s ?? '')) : false;
            if (!verified) finding('error', 'request-signature', 'request signature does not verify');
            return verified && path.ok ? { verified: true, signerJwk: jwk as Jwk } : { verified: false };
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

      const parsed = client.parseOpenid4vpAuthorizationRequest({ authorizationRequest: invocationUri });
      const { authorizationRequestPayload: request, client: resolvedClient } = await client.resolveOpenId4vpAuthorizationRequest({
        authorizationRequestPayload: parsed.params as never,
        responseMode: { type: 'direct_post' },
      });
      this.checkRequest(request as Record<string, unknown>, evidence, finding, resolvedClient);
      if (evidence.findings.some((f) => f.severity === 'error')) {
        throw new Error(`request refused: ${evidence.findings.filter((f) => f.severity === 'error').map((f) => f.code).join(', ')}`);
      }

      const query = request.dcql_query as { credentials: { id: string; claims?: { path: (string | number | null)[] }[] }[] };
      const [credentialQuery] = query.credentials;
      const disclose = [...new Set((credentialQuery.claims ?? []).map((claim) => String(claim.path[0])))];
      evidence.presentation = await presentSdJwtVc(credential, {
        holderPrivateKey: this.holderKey.privateKey,
        disclose,
        audience: request.client_id as string,
        nonce: request.nonce,
      });

      const metadata = request.client_metadata as { jwks?: { keys: JWK[] }; encrypted_response_enc_values_supported?: string[] };
      const verifierKey = metadata.jwks?.keys.find((k) => k.use === undefined || k.use === 'enc');
      if (!verifierKey) throw new Error('client_metadata has no encryption key');
      const enc = metadata.encrypted_response_enc_values_supported?.find((e) => SUPPORTED_ENC.includes(e)) ?? 'A128GCM';
      const payload = { vp_token: { [credentialQuery.id]: [evidence.presentation] }, ...(request.state ? { state: request.state } : {}) };
      evidence.responseJwe = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
        .setProtectedHeader({ alg: 'ECDH-ES', enc, ...(verifierKey.kid ? { kid: verifierKey.kid } : {}) })
        .encrypt(await importJWK(verifierKey, 'ECDH-ES'));

      const responseUri = request.response_uri as string;
      const exchange: HttpExchange = { method: 'POST', url: responseUri };
      evidence.response = exchange;
      const response = await fetch(responseUri, { method: 'POST', body: new URLSearchParams({ response: evidence.responseJwe }) });
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

  private checkRequest(
    request: Record<string, unknown>,
    evidence: PresentationEvidence,
    finding: (severity: WalletFinding['severity'], code: string, message: string) => void,
    client: { prefix?: string } | undefined,
  ) {
    const header = evidence.request?.header ?? {};
    if (header.typ !== 'oauth-authz-req+jwt') finding('warning', 'request-typ', `request object typ is ${String(header.typ)}, expected oauth-authz-req+jwt`);
    const clientId = String(request.client_id ?? '');
    if (!clientId.startsWith('x509_hash:')) finding('warning', 'client-id-prefix', `client_id ${clientId} does not use the x509_hash prefix (HAIP 1.0)`);
    if (client?.prefix && client.prefix !== 'x509_hash') finding('warning', 'client-id-prefix', `client identifier prefix ${client.prefix}`);
    if (request.response_mode !== 'direct_post.jwt') finding('error', 'response-mode', `response_mode ${String(request.response_mode)}, expected direct_post.jwt`);
    for (const key of ['response_uri']) {
      const value = request[key];
      if (typeof value !== 'string') finding('error', key, `${key} is missing`);
      else if (!value.startsWith('https://')) finding(this.options.allowInsecureUrls ? 'warning' : 'error', `${key}-not-https`, `${key} ${value} is not https`);
    }
    if (!request.dcql_query) finding('error', 'dcql-query', 'the request has no dcql_query');
    const verifierInfo = request.verifier_info as { format?: string }[] | undefined;
    if (!verifierInfo?.some((info) => info.format === 'registration_cert')) {
      finding('warning', 'registration-certificate', 'the request carries no registration certificate in verifier_info');
    }
  }
}

