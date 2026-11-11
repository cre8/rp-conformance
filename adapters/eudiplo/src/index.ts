import {
  type DcqlQuery,
  type DefaultQueryId,
  type Flow,
  type RelyingPartyAdapter,
  type RelyingPartyResult,
  type RunningServer,
  type StartedPresentation,
  sendJson,
  sendText,
  startServer,
  type TestEnvironment,
} from '@rp-conformance/core';

export interface EudiploAdapterOptions {
  /**
   * Base URL of EUDIPLO as the harness reaches it; default `EUDIPLO_URL`, or `http://127.0.0.1:<EUDIPLO_PORT>` (port 3000
   * by default). Not `localhost`: Docker publishes EUDIPLO on 127.0.0.1 only, and `localhost` may resolve to `::1` first.
   */
  baseUrl?: string;
  /** Root client of EUDIPLO (`AUTH_CLIENT_ID` / `AUTH_CLIENT_SECRET`). */
  clientId?: string;
  clientSecret?: string;
  /** Host name under which EUDIPLO reaches the harness services; default `host.docker.internal`. */
  harnessHost?: string;
  /** Port of the adapter's relying-party page for the DC API flow (on 127.0.0.1); default `EUDIPLO_PAGE_PORT` or a free port. */
  pagePort?: number;
}

/** A DC API presentation the adapter's page runs: EUDIPLO's signed request object and where the page posts the response. */
interface DcApiPage {
  requestObject: string;
  responseUri: string;
}

/** The fields of `GET /api/session/:id` the adapter reads. */
interface EudiploSession {
  id: string;
  status: 'active' | 'fetched' | 'completed' | 'expired' | 'failed' | 'cancelled';
  credentials?: { id: string; values: Record<string, unknown>[] }[];
  errorReason?: string;
  failureCode?: string;
  outcome?: unknown;
}

const PENDING = new Set(['active', 'fetched']);

/**
 * Adapter for EUDIPLO (harness design section 4.8). One tenant per namespace: `setUp` creates the tenant, imports the
 * access certificate with its key, and creates a presentation configuration per default query, trusting `TL-PID`
 * through `trusted_authorities` (`etsi_tl`, pinned to the scheme operator certificate) and carrying the registration
 * certificate. Presentations start with `POST /api/verifier/offer`, via redirects (`response_type` `uri`) or the DC API
 * (`dc-api`, answered on the adapter's own page); the result is `GET /api/session/:id`.
 */
export class EudiploAdapter implements RelyingPartyAdapter {
  readonly name = 'eudiplo';
  readonly harnessHost: string;
  private readonly baseUrl: string;
  private token?: string;
  private tenantId?: string;
  private skewSeconds?: number;
  private queries?: Record<DefaultQueryId, DcqlQuery>;
  /** The default query of each started transaction, to read its released attributes. */
  private readonly transactionQueries = new Map<string, DefaultQueryId>();
  /** The relying-party page of the DC API flow, by EUDIPLO session. */
  private readonly pages = new Map<string, DcApiPage>();
  private pageServer?: RunningServer;

  constructor(private readonly options: EudiploAdapterOptions = {}) {
    this.baseUrl = (options.baseUrl ?? process.env.EUDIPLO_URL ?? `http://127.0.0.1:${process.env.EUDIPLO_PORT ?? 3000}`).replace(/\/$/, '');
    this.harnessHost = options.harnessHost ?? process.env.HARNESS_HOST ?? 'host.docker.internal';
  }

  private async call<T>(method: string, path: string, body?: unknown, token = this.token): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: {
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await response.text();
    if (!response.ok) throw new Error(`EUDIPLO ${method} ${path}: HTTP ${response.status} ${text}`);
    return (text ? JSON.parse(text) : undefined) as T;
  }

  private async getToken(clientId: string, clientSecret: string): Promise<string> {
    const { access_token } = await this.call<{ access_token: string }>(
      'POST',
      '/api/oauth2/token',
      { grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret },
      undefined,
    );
    return access_token;
  }

  async setUp(env: TestEnvironment, namespace: string): Promise<void> {
    await this.startPageServer();
    const rootToken = await this.getToken(
      this.options.clientId ?? process.env.EUDIPLO_CLIENT_ID ?? 'rp-conformance',
      this.options.clientSecret ?? process.env.EUDIPLO_CLIENT_SECRET ?? 'rp-conformance-secret',
    );
    // Tenant IDs are lowercase letters, digits, '-' and '_', at most 63 characters.
    this.tenantId = namespace.toLowerCase().replace(/[^a-z0-9_-]/g, '-').slice(0, 63);
    const tenant = await this.call<{ client: { clientId: string; clientSecret: string } }>(
      'POST',
      '/api/tenant',
      {
        id: this.tenantId,
        name: `RP conformance ${namespace}`,
        description: 'Created by the RP conformance harness',
        roles: ['presentation:manage', 'presentation:request'],
      },
      rootToken,
    );
    this.token = await this.getToken(tenant.client.clientId, tenant.client.clientSecret);

    const { id: accessKeyChainId } = await this.call<{ id: string }>('POST', '/api/key-chain/import', {
      description: 'Access certificate issued by AC-A',
      usageType: 'access',
      keyPem: env.accessCertificate.privateKeyPem,
      crt: env.accessCertificate.chainPem,
    });

    const pidList = env.trustLists.find((list) => list.id === 'TL-PID');
    if (!pidList) throw new Error('TL-PID is not published');
    const operatorDer = pidList.schemeOperatorCertificatePem
      .replace(/-----(BEGIN|END) CERTIFICATE-----/g, '')
      .replace(/\s+/g, '');
    this.skewSeconds = Number(env.ics.items['RP.P.4'] ?? 60);
    this.queries = env.queries;

    for (const [id, query] of Object.entries(env.queries)) {
      // The ICS declares RP.P.3 No: EUDIPLO is configured with trusted_authorities of its own (etsi_tl below), so the
      // aki-restricted variant of default_query_pid (TrustMechanisms_016) is not configured.
      if (query.credentials.some((credential) => credential.trusted_authorities)) continue;
      await this.call('POST', '/api/verifier/config', {
        id,
        description: `FCAF ${id}`,
        dcql_query: {
          // EUDIPLO 9.1.0 rejects require_cryptographic_holder_binding; its DCQL default is true (OpenID4VP 1.0 section 6.1).
          credentials: query.credentials.map(({ require_cryptographic_holder_binding: _required, ...credential }) => ({
            ...credential,
            trusted_authorities: [{ type: 'etsi_tl', values: [{ url: pidList.url, verifierX509Der: operatorDer }] }],
          })),
        },
        registration_cert: { jwt: env.registrationCertificate },
        accessKeyChainId,
        skewSeconds: this.skewSeconds,
        statusCheckMode: 'strict',
      });
    }
  }

  /** The Origin of the adapter's relying-party page, which EUDIPLO signs into `expected_origins`. */
  private get pageOrigin(): string {
    if (!this.pageServer) throw new Error('the EUDIPLO adapter is not set up');
    return this.pageServer.localUrl;
  }

  /**
   * EUDIPLO has no page of its own for the DC API, so the adapter serves a minimal relying-party page on its own origin
   * (127.0.0.1, which a browser treats as a secure context), as a relying party's frontend would.
   */
  private async startPageServer() {
    if (this.pageServer) return;
    const port = this.options.pagePort ?? Number(process.env.EUDIPLO_PAGE_PORT ?? 0);
    this.pageServer = await startServer({ host: '127.0.0.1', port }, (req, res) => {
      const match = /^\/dc-api\/([^/?]+)$/.exec(new URL(req.url ?? '/', 'http://localhost').pathname);
      const page = match && this.pages.get(decodeURIComponent(match[1]));
      if (req.method !== 'GET' || !page) return sendJson(res, 404, { error: 'not_found' });
      return sendText(res, 200, dcApiPage(page), 'text/html; charset=utf-8');
    });
  }

  async startPresentation(req: { query: DefaultQueryId; flow: Flow }): Promise<StartedPresentation> {
    if (req.flow === 'dc-api') return this.startDcApiPresentation(req.query);
    const offer = await this.call<{ uri: string; session: string }>('POST', '/api/verifier/offer', {
      response_type: 'uri',
      requestId: req.query,
      skewSeconds: this.skewSeconds,
    });
    this.transactionQueries.set(offer.session, req.query);
    return { transactionId: offer.session, invocation: { uri: offer.uri } };
  }

  /**
   * `POST /api/verifier/offer` with `response_type` `dc-api` and the page's Origin as `expected_origin`, then the signed
   * request object EUDIPLO stored for the session (`GET /api/session/:id`, or its `request_uri`). The page passes it to
   * `navigator.credentials.get` and posts the returned `data` to the request's `response_uri`
   * (`POST /presentations/:id/oid4vp`), as EUDIPLO's SDK does.
   */
  private async startDcApiPresentation(query: DefaultQueryId): Promise<StartedPresentation> {
    const offer = await this.call<{ uri: string; session: string }>('POST', '/api/verifier/offer', {
      response_type: 'dc-api',
      requestId: query,
      expected_origin: this.pageOrigin,
      skewSeconds: this.skewSeconds,
    });
    this.transactionQueries.set(offer.session, query);
    const session = await this.call<{ requestObject?: string }>('GET', `/api/session/${offer.session}`);
    let requestObject = session.requestObject;
    if (!requestObject) {
      const requestUri = new URLSearchParams(offer.uri.replace(/^[^?]*\?/, '')).get('request_uri');
      if (!requestUri) throw new Error('EUDIPLO returned neither a request object nor a request_uri for the DC API session');
      const fetched = await fetch(requestUri, { headers: { accept: 'application/oauth-authz-req+jwt' } });
      if (!fetched.ok) throw new Error(`EUDIPLO GET ${requestUri}: HTTP ${fetched.status}`);
      requestObject = await fetched.text();
    }
    const payload = JSON.parse(Buffer.from(requestObject.split('.')[1] ?? '', 'base64url').toString('utf8')) as { response_uri?: unknown };
    if (typeof payload.response_uri !== 'string') throw new Error('the request object of the DC API session has no response_uri');
    this.pages.set(offer.session, { requestObject, responseUri: payload.response_uri });
    return { transactionId: offer.session, invocation: { dcApiPage: `${this.pageOrigin}/dc-api/${encodeURIComponent(offer.session)}` } };
  }

  /**
   * The released attributes in the shape of the query's claim paths. EUDIPLO reports the elements of an mdoc as one
   * flat map over all namespaces; each element goes back under the namespace the query requested it in, and an element
   * the query did not request under the first requested namespace, so the evaluation still sees it.
   */
  private releasedAttributes(transactionId: string, values: Record<string, unknown>): Record<string, unknown> {
    const query = this.queries?.[this.transactionQueries.get(transactionId) ?? 'default_query_pid'];
    const credential = query?.credentials[0];
    if (credential?.format !== 'mso_mdoc') return values;
    const paths = (credential.claims ?? []).map((claim) => claim.path.map(String));
    const released: Record<string, Record<string, unknown>> = {};
    for (const [element, value] of Object.entries(values)) {
      const namespace = paths.find((path) => path[1] === element)?.[0] ?? paths[0]?.[0] ?? 'unknown';
      (released[namespace] ??= {})[element] = value;
    }
    return released;
  }

  async readResult(transactionId: string, timeoutMs: number): Promise<RelyingPartyResult> {
    const deadline = Date.now() + timeoutMs;
    let session: EudiploSession;
    do {
      session = await this.call<EudiploSession>('GET', `/api/session/${transactionId}`);
      if (!PENDING.has(session.status)) break;
      await new Promise((resolve) => setTimeout(resolve, 250));
    } while (Date.now() < deadline);
    if (PENDING.has(session.status)) return { outcome: 'pending', raw: session };
    if (session.status === 'completed') {
      const values = Object.assign({}, ...(session.credentials ?? []).flatMap((c) => c.values));
      return { outcome: 'success', releasedAttributes: this.releasedAttributes(transactionId, values), raw: session };
    }
    return { outcome: 'failure', raw: session };
  }

  async refreshTrust(): Promise<void> {
    await this.call('DELETE', '/api/cache/trust-list');
  }

  async tearDown(): Promise<void> {
    await this.pageServer?.close();
    this.pageServer = undefined;
  }
}

/**
 * The adapter's relying-party page: it passes EUDIPLO's signed request to `navigator.credentials.get` (protocol
 * `openid4vp-v1-signed`) and posts the returned `data` as JSON to the request's `response_uri`, which EUDIPLO opens to
 * every origin (CORS) for this purpose.
 */
function dcApiPage(page: DcApiPage): string {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>EUDIPLO relying party</title></head>
<body>
<p id="status">Requesting a credential</p>
<script type="module">
const status = document.getElementById('status');
try {
  const credential = await navigator.credentials.get({
    mediation: 'required',
    digital: { requests: [{ protocol: 'openid4vp-v1-signed', data: { request: ${JSON.stringify(page.requestObject)} } }] },
  });
  const response = await fetch(${JSON.stringify(page.responseUri)}, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ...credential.data }),
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

export function createAdapter(): RelyingPartyAdapter {
  return new EudiploAdapter();
}
