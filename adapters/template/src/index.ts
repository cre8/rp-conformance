// Template of a Relying Party adapter: copy this file, replace the HTTP calls to "my RP" with the API of your Relying
// Party, and run it with
//
//   pnpm eudi-pcaf run --adapter ./my-adapter.ts --ics my-ics.yaml
//
// The walkthrough is in adapter-guide.md. The Relying Party API this template assumes is made up, and every call to
// it is marked `TODO`:
//
//   PUT    /admin/tenants/:tenant                 configure a tenant (trust, certificates, queries, settings)
//   POST   /admin/tenants/:tenant/trust/refresh   fetch the trust lists now
//   DELETE /admin/tenants/:tenant                 remove the tenant
//   POST   /presentations                         start a presentation: { id, requestUri } or { id, dcApiPage }
//   GET    /presentations/:id                     its result: { status: pending | verified | rejected, attributes?, flags? }
//   GET    /version                               { version }
//
// The adapter is the only code of the harness that knows your Relying Party. It does three things: configure the
// Relying Party with what the harness publishes (`setUp`), start presentations (`startPresentation`) and report what the
// Relying Party decided (`readResult`). The harness plays the wallet, the issuers, the status lists and the trust lists.
import {
  type CredentialCategory,
  categoryOfCredentialQuery,
  type DcqlQuery,
  type DefaultQueryId,
  durationMs,
  type Flow,
  type RelyingPartyAdapter,
  type RelyingPartyResult,
  type StartedPresentation,
  type TestEnvironment,
} from '@eudi-pcaf/core';

/** Where the harness reaches your Relying Party. Use 127.0.0.1, not localhost (adapter-guide.md, "Networking"). */
const RP_URL = (process.env.MY_RP_URL ?? 'http://127.0.0.1:8080').replace(/\/$/, '');
/** Whatever your admin API needs; pass it into the Docker image or the GitHub Action with `env-vars`. */
const RP_TOKEN = process.env.MY_RP_TOKEN;

/** The ICS item that declares whether the Relying Party requests a category (RP.G.3 to RP.G.5); PIDs always. */
const CATEGORY_ICS: Record<Exclude<CredentialCategory, 'pid'>, string> = { qeaa: 'RP.G.3', 'pub-eaa': 'RP.G.4', eaa: 'RP.G.5' };

/** What `GET /presentations/:id` of "my RP" answers. TODO: your Relying Party's verification result. */
interface MyRpResult {
  status: 'pending' | 'verified' | 'rejected';
  /** The attributes it released to the relying service: nested objects or keys joined with `.`. */
  attributes?: Record<string, unknown>;
  /** For example `status-unknown` or `trust-list-stale`. */
  flags?: string[];
}

export class MyRelyingPartyAdapter implements RelyingPartyAdapter {
  readonly name = 'my-rp';
  /**
   * The host name under which your Relying Party reaches the harness's trust list and status list servers. 127.0.0.1
   * when it runs on the host; `host.docker.internal` when it runs in a container (map that name to `host-gateway` in
   * its Compose file). `--harness-host` overrides it.
   */
  readonly harnessHost = process.env.HARNESS_HOST ?? '127.0.0.1';
  private tenant?: string;

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const response = await fetch(`${RP_URL}${path}`, {
      method,
      headers: {
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...(RP_TOKEN ? { authorization: `Bearer ${RP_TOKEN}` } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await response.text();
    if (!response.ok) throw new Error(`my RP ${method} ${path}: HTTP ${response.status} ${text}`);
    return (text ? JSON.parse(text) : undefined) as T;
  }

  /**
   * Called once per run, before any test case. `namespace` is new for every run: the URLs of the trust lists contain
   * it, so a configuration left from an earlier run cannot be mistaken for this one. Keep the run apart with it, for
   * example as a tenant, or replace your Relying Party's whole configuration.
   */
  async setUp(env: TestEnvironment, namespace: string): Promise<void> {
    this.tenant = namespace;
    const requested = (category: CredentialCategory) => category === 'pid' || String(env.ics.items[CATEGORY_ICS[category]]) === 'Yes';
    const ms = (item: string) => durationMs(String(env.ics.items[item] ?? ''));

    // TODO: replace with your Relying Party's configuration API.
    await this.call('PUT', `/admin/tenants/${encodeURIComponent(namespace)}`, {
      // Roots of trust, one per credential category (adapter-guide.md, "What setUp configures"). Each list is fetched
      // from `url` and its seal verified with the scheme operator certificate; the Relying Party must not trust any
      // other key for it. TL-PID: PID Providers and their status list signers. TL-PUB: PuB-EAA Providers.
      trustLists: env.trustLists
        .filter((list) => list.id === 'TL-PID' || (list.id === 'TL-PUB' && requested('pub-eaa')))
        .map((list) => ({ id: list.id, type: list.loteType, url: list.url, signerCertificatePem: list.schemeOperatorCertificatePem })),
      // QEAAs: the test LOTL (ETSI TS 119 612), pinned to its signing certificates; it points to TL-QEAA.
      ...(requested('qeaa')
        ? { listOfTrustedLists: { url: env.listOfTrustedLists.url, signingCertificatesPem: env.listOfTrustedLists.signingCertificatesPem } }
        : {}),
      // Non-qualified EAAs: the anchor the rulebook of default_credential_eaa defines; no list publishes it.
      ...(requested('eaa')
        ? { rulebookAnchorsPem: env.rulebooks.find((r) => r.credential === 'default_credential_eaa')?.anchorsPem ?? [] }
        : {}),
      // The Relying Party signs its requests with the access certificate (x509_hash client ID) and sends the
      // registration certificate in `verifier_info`.
      accessCertificate: { chainPem: env.accessCertificate.chainPem, privateKeyPem: env.accessCertificate.privateKeyPem },
      registrationCertificate: env.registrationCertificate,
      // The DCQL query of every default query, by its ID; `startPresentation` names one of them.
      queries: queriesFor(env, requested),
      // The ICS describes the Relying Party. Where your Relying Party has a setting for an item, set it from the ICS
      // here; where it has a fixed value, declare that value in the ICS instead.
      settings: {
        clockSkewSeconds: Number(env.ics.items['RP.P.4'] ?? 60),
        keyBindingMaxAgeSeconds: Number(env.ics.items['RP.P.6'] ?? 300),
        transactionLifetimeMs: ms('RP.P.7'),
        statusListTimeoutMs: ms('RP.R.6'),
        statusListMaxAgeMs: ms('RP.R.7'),
        refuseFutureStatusListIat: env.ics.items['RP.R.8'] === 'Yes',
        trustListRefreshMs: ms('RP.T.1'),
        trustListGraceMs: ms('RP.T.2') ?? 0,
      },
    });
  }

  /**
   * Start a presentation of the default query `query` in `flow`. For `redirect`, return the URI the wallet would be
   * invoked with (`openid4vp://?client_id=…&request_uri=…`). For `dc-api`, return the URL of a page of your Relying
   * Party that calls `navigator.credentials.get` and forwards the response to its back end (adapter-guide.md,
   * "The DC API flow").
   */
  async startPresentation(req: { query: DefaultQueryId; flow: Flow }): Promise<StartedPresentation> {
    // TODO: replace with your Relying Party's API.
    const started = await this.call<{ id: string; requestUri?: string; dcApiPage?: string }>('POST', '/presentations', {
      tenant: this.tenant,
      query: req.query,
      responseMode: req.flow === 'dc-api' ? 'dc_api.jwt' : 'direct_post.jwt',
    });
    if (req.flow === 'dc-api') {
      if (!started.dcApiPage) throw new Error('my RP returned no page for the DC API flow');
      return { transactionId: started.id, invocation: { dcApiPage: started.dcApiPage } };
    }
    if (!started.requestUri) throw new Error('my RP returned no request URI');
    return { transactionId: started.id, invocation: { uri: started.requestUri } };
  }

  /**
   * What the Relying Party decided, once it has: `success` with the attributes it released to the relying service,
   * `failure` when it rejected the presentation, or `pending` when it has not decided by `timeoutMs`. Report what the
   * relying service would get, not what the wallet sent: the harness compares the attributes with the ones requested.
   */
  async readResult(transactionId: string, timeoutMs: number): Promise<RelyingPartyResult> {
    const deadline = Date.now() + timeoutMs;
    let result: MyRpResult;
    do {
      // TODO: replace with your Relying Party's API.
      result = await this.call<MyRpResult>('GET', `/presentations/${encodeURIComponent(transactionId)}`);
      if (result.status !== 'pending') break;
      await new Promise((resolve) => setTimeout(resolve, 250));
    } while (Date.now() < deadline);
    return {
      outcome: result.status === 'verified' ? 'success' : result.status === 'rejected' ? 'failure' : 'pending',
      ...(result.status === 'verified' ? { releasedAttributes: result.attributes ?? {} } : {}),
      ...(result.flags?.length ? { flags: result.flags } : {}),
      raw: result,
    };
  }

  /**
   * Optional. The trust list test cases publish a new version of a list and wait for the Relying Party to fetch it:
   * with this hook up to 10 seconds, without it the whole refresh interval the ICS declares (RP.T.1).
   */
  async refreshTrust(): Promise<void> {
    // TODO: replace with your Relying Party's API, or remove the method.
    await this.call('POST', `/admin/tenants/${encodeURIComponent(this.tenant ?? '')}/trust/refresh`);
  }

  /** Optional. Recorded in the report: which build of your Relying Party was tested. */
  async describe(): Promise<Record<string, string>> {
    // TODO: replace with your Relying Party's API, or remove the method.
    const { version } = await this.call<{ version?: string }>('GET', '/version').catch(() => ({ version: undefined }));
    return { url: RP_URL, ...(version ? { version } : {}) };
  }

  /** Optional. Called after the last test case. */
  async tearDown(): Promise<void> {
    // TODO: replace with your Relying Party's API, or remove the method.
    if (this.tenant) await this.call('DELETE', `/admin/tenants/${encodeURIComponent(this.tenant)}`).catch(() => undefined);
  }

  // Not implemented: `frontEnd`, for a Relying Party that redeems the response code at its own front end (ICS RP.P.9
  // Yes; adapter-guide.md, "Optional hooks"). With RP.P.9 No the test cases that need it are NOT APPLICABLE.
}

/**
 * The default queries the Relying Party is configured with: those of the categories the ICS declares. The variants with
 * `trusted_authorities` (TrustMechanisms_016) are needed only with RP.P.3 Yes.
 */
function queriesFor(env: TestEnvironment, requested: (category: CredentialCategory) => boolean): Record<string, DcqlQuery> {
  return Object.fromEntries(
    Object.entries(env.queries).filter(([, query]) => {
      if (String(env.ics.items['RP.P.3']) !== 'Yes' && query.credentials.some((c) => c.trusted_authorities)) return false;
      return query.credentials.every((credential) => requested(categoryOfCredentialQuery(credential.id)));
    }),
  );
}

/** The harness calls this to get the adapter; the module must export it. */
export function createAdapter(): RelyingPartyAdapter {
  return new MyRelyingPartyAdapter();
}
