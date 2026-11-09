import type {
  DefaultQueryId,
  Flow,
  RelyingPartyAdapter,
  RelyingPartyResult,
  StartedPresentation,
  TestEnvironment,
} from '@rp-conformance/core';

export interface EudiploAdapterOptions {
  /** Base URL of EUDIPLO as the harness reaches it; default `EUDIPLO_URL` or `http://localhost:3000`. */
  baseUrl?: string;
  /** Root client of EUDIPLO (`AUTH_CLIENT_ID` / `AUTH_CLIENT_SECRET`). */
  clientId?: string;
  clientSecret?: string;
  /** Host name under which EUDIPLO reaches the harness services; default `host.docker.internal`. */
  harnessHost?: string;
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
 * certificate. Presentations start with `POST /api/verifier/offer`; the result is `GET /api/session/:id`.
 */
export class EudiploAdapter implements RelyingPartyAdapter {
  readonly name = 'eudiplo';
  readonly harnessHost: string;
  private readonly baseUrl: string;
  private token?: string;
  private tenantId?: string;
  private skewSeconds?: number;

  constructor(private readonly options: EudiploAdapterOptions = {}) {
    this.baseUrl = (options.baseUrl ?? process.env.EUDIPLO_URL ?? 'http://localhost:3000').replace(/\/$/, '');
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

  async startPresentation(req: { query: DefaultQueryId; flow: Flow }): Promise<StartedPresentation> {
    if (req.flow !== 'redirect') throw new Error(`flow ${req.flow} is not implemented by the EUDIPLO adapter in Phase 0`);
    const offer = await this.call<{ uri: string; session: string }>('POST', '/api/verifier/offer', {
      response_type: 'uri',
      requestId: req.query,
      skewSeconds: this.skewSeconds,
    });
    return { transactionId: offer.session, invocation: { uri: offer.uri } };
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
      const releasedAttributes = Object.assign({}, ...(session.credentials ?? []).flatMap((c) => c.values));
      return { outcome: 'success', releasedAttributes, raw: session };
    }
    return { outcome: 'failure', raw: session };
  }

  async refreshTrust(): Promise<void> {
    await this.call('DELETE', '/api/cache/trust-list');
  }
}

export function createAdapter(): RelyingPartyAdapter {
  return new EudiploAdapter();
}
