import {
  durationMs,
  type DefaultQueryId,
  type Flow,
  type FrontEndResult,
  type RelyingPartyAdapter,
  type RelyingPartyResult,
  type StartedPresentation,
  type TestEnvironment,
} from '@rp-conformance/core';
import { ReferenceRelyingParty, type ReferenceRpResult, USER_SESSION_COOKIE } from '@rp-conformance/reference-rp';

export interface ReferenceAdapterOptions {
  /** Port of the reference Relying Party; 0 picks a free port. */
  port?: number;
}

/** Drives the reference Relying Party, which it runs in-process (harness design section 7). */
export class ReferenceAdapter implements RelyingPartyAdapter {
  readonly name = 'reference';
  private rp?: ReferenceRelyingParty;
  /** The user session of the user agent that started each transaction (its cookie at the front end). */
  private readonly userSessions = new Map<string, string>();

  constructor(private readonly options: ReferenceAdapterOptions = {}) {}

  async setUp(env: TestEnvironment): Promise<void> {
    this.rp = await new ReferenceRelyingParty({
      port: this.options.port ?? 0,
      host: '127.0.0.1',
      trustLists: env.trustLists,
      listOfTrustedLists: env.listOfTrustedLists,
      rulebooks: env.rulebooks,
      accessCertificate: env.accessCertificate,
      registrationCertificate: env.registrationCertificate,
      queries: env.queries,
      skewSeconds: Number(env.ics.items['RP.P.4'] ?? 60),
      kbMaxAgeSeconds: Number(env.ics.items['RP.P.6'] ?? 300),
      maxStatusListBytes: Number(env.ics.items['RP.R.4'] ?? 1048576),
      allowInsecureUrls: true,
      graceMs: durationMs(String(env.ics.items['RP.T.2'] ?? '')) ?? 0,
      maxResponseBytes: Number(env.ics.items['RP.P.11'] ?? 0) || undefined,
      cacheStatusLists: env.ics.items['RP.R.5'] === 'Yes',
      statusTimeoutMs: durationMs(String(env.ics.items['RP.R.6'] ?? '')),
      statusListFreshness: {
        maxAgeSeconds: (durationMs(String(env.ics.items['RP.R.7'] ?? '')) ?? Number.NaN) / 1000 || undefined,
        refuseFutureIat: env.ics.items['RP.R.8'] === 'Yes',
      },
      rejectPastExpiryDate: /^reject/i.test(String(env.ics.items['RP.P.12'] ?? '')),
      requireIssuerInCertificate: env.ics.items['RP.P.13'] === 'Yes',
      transactionLifetimeMs: durationMs(String(env.ics.items['RP.P.7'] ?? '')),
    }).start();
    const failed = (await this.rp.refreshTrust()).filter((list) => list.error);
    if (failed.length > 0) throw new Error(`reference RP could not load: ${failed.map((l) => l.error).join('; ')}`);
  }

  private get url(): string {
    if (!this.rp) throw new Error('reference adapter not set up');
    return this.rp.url;
  }

  async startPresentation(req: { query: DefaultQueryId; flow: Flow }): Promise<StartedPresentation> {
    const response = await fetch(`${this.url}/api/presentations`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(req),
    });
    if (response.status !== 201) throw new Error(`start presentation: HTTP ${response.status} ${await response.text()}`);
    const started = (await response.json()) as { transactionId: string; uri?: string; dcApiPage?: string; userSession?: string };
    if (started.userSession) this.userSessions.set(started.transactionId, started.userSession);
    if (started.dcApiPage) return { transactionId: started.transactionId, invocation: { dcApiPage: started.dcApiPage } };
    return { transactionId: started.transactionId, invocation: { uri: started.uri as string } };
  }

  async readResult(transactionId: string, timeoutMs: number): Promise<RelyingPartyResult> {
    const deadline = Date.now() + timeoutMs;
    let result: ReferenceRpResult;
    do {
      const response = await fetch(`${this.url}/api/presentations/${transactionId}`);
      result = (await response.json()) as ReferenceRpResult;
      if (result.status !== 'pending') break;
      await new Promise((resolve) => setTimeout(resolve, 200));
    } while (Date.now() < deadline);
    return {
      outcome: result.status,
      releasedAttributes: result.attributes,
      ...(result.flags ? { flags: result.flags } : {}),
      raw: result,
    };
  }

  /**
   * The reference Relying Party's front end (`/done/<id>`): the user agent that started the transaction sends its
   * session cookie, a fresh user agent none. Without `url` the user agent opens the front end without a response code.
   */
  async frontEnd(req: { transactionId: string; url?: string; userAgent: 'same' | 'fresh' }): Promise<FrontEndResult> {
    const session = req.userAgent === 'same' ? this.userSessions.get(req.transactionId) : undefined;
    const response = await fetch(req.url ?? `${this.url}/done/${encodeURIComponent(req.transactionId)}`, {
      headers: session ? { cookie: `${USER_SESSION_COOKIE}=${session}` } : {},
      redirect: 'manual',
    });
    const text = await response.text();
    let body: { status?: string; attributes?: Record<string, unknown> } | string = text;
    try {
      body = JSON.parse(text);
    } catch {
      // not JSON: nothing released
    }
    const attributes = typeof body === 'object' && body.status === 'success' ? body.attributes : undefined;
    return { released: response.ok && Boolean(attributes), ...(attributes ? { attributes } : {}), status: response.status, raw: body };
  }

  async refreshTrust(): Promise<void> {
    await fetch(`${this.url}/api/trust/refresh`, { method: 'POST' });
  }

  async tearDown(): Promise<void> {
    await this.rp?.stop();
  }
}

export function createAdapter(): RelyingPartyAdapter {
  return new ReferenceAdapter();
}
