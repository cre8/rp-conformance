import type {
  DefaultQueryId,
  Flow,
  RelyingPartyAdapter,
  RelyingPartyResult,
  StartedPresentation,
  TestEnvironment,
} from '@rp-conformance/core';
import { ReferenceRelyingParty, type ReferenceRpResult } from '@rp-conformance/reference-rp';

export interface ReferenceAdapterOptions {
  /** Port of the reference Relying Party; 0 picks a free port. */
  port?: number;
}

/** Drives the reference Relying Party, which it runs in-process (harness design section 7). */
export class ReferenceAdapter implements RelyingPartyAdapter {
  readonly name = 'reference';
  private rp?: ReferenceRelyingParty;

  constructor(private readonly options: ReferenceAdapterOptions = {}) {}

  async setUp(env: TestEnvironment): Promise<void> {
    this.rp = await new ReferenceRelyingParty({
      port: this.options.port ?? 0,
      host: '127.0.0.1',
      trustLists: env.trustLists,
      accessCertificate: env.accessCertificate,
      registrationCertificate: env.registrationCertificate,
      queries: env.queries,
      skewSeconds: Number(env.ics.items['RP.P.4'] ?? 60),
      kbMaxAgeSeconds: Number(env.ics.items['RP.P.6'] ?? 300),
      allowInsecureUrls: true,
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
    const { transactionId, uri } = (await response.json()) as { transactionId: string; uri: string };
    return { transactionId, invocation: { uri } };
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
      raw: result,
    };
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
