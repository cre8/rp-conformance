// The DC API shim (harness design section 4.5): Playwright opens the Relying Party's page with an init script that
// replaces `navigator.credentials.get`. A digital credential request goes to the Conformance Wallet through an exposed
// binding, together with the Origin of the calling frame as the browser knows it, and the page's promise resolves
// with the wallet's answer as a `DigitalCredential`. The page keeps its real origin, so `expected_origins` and the
// `origin:` audience behave as with a platform wallet; the platform's own credential selection is not tested.
import { type Browser, chromium, type Request } from 'playwright';

/** One entry of `digital.requests` the page passed to `navigator.credentials.get`. */
export interface DcApiRequest {
  protocol: string;
  data: unknown;
}

/** A call of `navigator.credentials.get` with a digital credential request. */
export interface DcApiCall {
  /** The Origin of the calling frame, serialised by the browser (`https://rp.example`, no trailing slash). */
  origin: string;
  /** The URL of the calling frame. */
  pageUrl: string;
  requests: DcApiRequest[];
  mediation: string | null;
}

/**
 * How the shim settles the page's promise: resolve it with the wallet's `DigitalCredential`, reject it as the
 * platform would (for example `NotAllowedError` when the user declines), or leave it pending, so that no response
 * reaches the page. `marker` is a string the page's delivery of the response to its backend contains, for example the
 * JWE, so the shim can find that request and its HTTP answer.
 */
export type DcApiOutcome =
  | { kind: 'respond'; protocol: string; data: Record<string, unknown>; marker?: string }
  | { kind: 'reject'; name: string; message: string }
  | { kind: 'withhold' };

/** A request the page made, with the answer it received. */
export interface NetworkExchange {
  at: string;
  method: string;
  url: string;
  postData?: string;
  status?: number;
  contentType?: string;
  body?: string;
  error?: string;
}

export interface DcApiRun {
  pageUrl: string;
  /** Every digital credential request of the page; the shim answers the first. */
  calls: DcApiCall[];
  outcome?: DcApiOutcome;
  /** The request in which the page forwarded the response, found by the outcome's `marker`. */
  delivery?: NetworkExchange;
  network: NetworkExchange[];
  console: string[];
  pageErrors: string[];
  /** Why the run did not complete: the page did not load, did not call the API, or did not forward the response. */
  error?: string;
}

export interface DcApiRunOptions {
  /** Milliseconds to wait for the page's call of `navigator.credentials.get`; default 15 s. */
  callTimeoutMs?: number;
  /** Milliseconds to wait for the page to forward the response and receive an answer; default 15 s. */
  deliveryTimeoutMs?: number;
}

const BINDING = '__rpConformanceDcApi';
/** Bodies kept as evidence are cut to this length. */
const MAX_BODY = 8192;

/**
 * Runs in every frame before the page's own scripts. It keeps `navigator.credentials.get` for other credential types
 * and answers digital credential requests through the binding, with a `DigitalCredential` (`protocol`, `data`).
 */
export const SHIM_SCRIPT = `(() => {
  const binding = ${JSON.stringify(BINDING)};
  const container = navigator.credentials;
  const original = container && typeof container.get === 'function' ? container.get.bind(container) : undefined;
  if (typeof globalThis.DigitalCredential !== 'function') {
    globalThis.DigitalCredential = function DigitalCredential() { throw new TypeError('Illegal constructor'); };
  }
  try {
    globalThis.DigitalCredential.userAgentAllowsProtocol = (protocol) => String(protocol).startsWith('openid4vp-v1-');
  } catch {}
  const credentialOf = (protocol, data) => {
    const credential = Object.create(globalThis.DigitalCredential.prototype);
    Object.defineProperties(credential, {
      id: { value: '', enumerable: true },
      type: { value: 'digital', enumerable: true },
      protocol: { value: protocol, enumerable: true },
      data: { value: data, enumerable: true },
      toJSON: { value: () => ({ id: '', type: 'digital', protocol, data }) },
    });
    return credential;
  };
  const get = async (options) => {
    if (!options || !options.digital) {
      if (original) return original(options);
      throw new DOMException('the harness answers only digital credential requests', 'NotSupportedError');
    }
    if (options.signal && options.signal.aborted) throw new DOMException('the request was aborted', 'AbortError');
    const requests = JSON.parse(JSON.stringify(options.digital.requests ?? []));
    const outcome = await globalThis[binding]({ requests, mediation: options.mediation ?? null });
    if (outcome.kind === 'reject') throw new DOMException(outcome.message, outcome.name);
    if (outcome.kind === 'withhold') return new Promise(() => {});
    return credentialOf(outcome.protocol, outcome.data);
  };
  if (container) Object.defineProperty(container, 'get', { value: get, configurable: true, writable: true });
  else Object.defineProperty(Navigator.prototype, 'credentials', { value: { get }, configurable: true });
})();`;

const cut = (text: string | undefined | null) => (text && text.length > MAX_BODY ? `${text.slice(0, MAX_BODY)}…` : (text ?? undefined));

/** The Playwright browser of a run, with one fresh browser context per presentation. */
export class DcApiShim {
  private constructor(private readonly browser: Browser) {}

  /**
   * Launches Chromium (the headless shell). Install it once with
   * `pnpm --filter @rp-conformance/dc-api-shim exec playwright install --only-shell chromium`.
   */
  static async launch(): Promise<DcApiShim> {
    try {
      return new DcApiShim(await chromium.launch({ headless: true }));
    } catch (error) {
      throw new Error(
        `the DC API shim could not launch Chromium (pnpm --filter @rp-conformance/dc-api-shim exec playwright install --only-shell chromium): ${(error as Error).message.split('\n')[0]}`,
      );
    }
  }

  async close(): Promise<void> {
    await this.browser.close();
  }

  /**
   * Opens `pageUrl`, hands the page's first digital credential request to `answer`, settles the page's promise with
   * its outcome, and waits until the page forwarded the response (the request whose body contains the outcome's
   * `marker`) and received an answer. Every request of the page is kept as evidence.
   */
  async run(pageUrl: string, answer: (call: DcApiCall) => Promise<DcApiOutcome>, options: DcApiRunOptions = {}): Promise<DcApiRun> {
    const run: DcApiRun = { pageUrl, calls: [], network: [], console: [], pageErrors: [] };
    const context = await this.browser.newContext();
    const exchanges = new Map<Request, NetworkExchange>();
    let settle: (outcome: DcApiOutcome | undefined) => void = () => {};
    const answered = new Promise<DcApiOutcome | undefined>((resolve) => {
      settle = resolve;
    });
    try {
      const page = await context.newPage();
      await page.exposeBinding(BINDING, async (source, payload: { requests: DcApiRequest[]; mediation: string | null }) => {
        const frameUrl = source.frame.url();
        const call: DcApiCall = { origin: new URL(frameUrl).origin, pageUrl: frameUrl, requests: payload.requests, mediation: payload.mediation };
        run.calls.push(call);
        if (run.calls.length > 1) return { kind: 'reject', name: 'NotAllowedError', message: 'the Conformance Wallet answers one request per page' };
        try {
          const outcome = await answer(call);
          run.outcome = outcome;
          settle(outcome);
          return outcome.kind === 'respond' ? { kind: 'respond', protocol: outcome.protocol, data: outcome.data } : outcome;
        } catch (error) {
          run.error = `the Conformance Wallet failed: ${(error as Error).message}`;
          settle(undefined);
          return { kind: 'reject', name: 'UnknownError', message: 'the Conformance Wallet failed' };
        }
      });
      await page.addInitScript(SHIM_SCRIPT);
      page.on('request', (request) => {
        exchanges.set(request, { at: new Date().toISOString(), method: request.method(), url: request.url(), postData: request.postData() ?? undefined });
      });
      // The status as soon as the headers arrive: a page need not read the body, and then the request never finishes.
      page.on('response', (response) => {
        const exchange = exchanges.get(response.request());
        if (!exchange) return;
        exchange.status = response.status();
        exchange.contentType = response.headers()['content-type'];
      });
      page.on('requestfinished', async (request) => {
        const exchange = exchanges.get(request);
        const response = await request.response().catch(() => null);
        if (exchange && response) exchange.body = cut(await response.text().catch(() => undefined));
      });
      page.on('requestfailed', (request) => {
        const exchange = exchanges.get(request);
        if (exchange) exchange.error = request.failure()?.errorText ?? 'failed';
      });
      page.on('console', (message) => void run.console.push(`${message.type()}: ${message.text()}`));
      page.on('pageerror', (error) => void run.pageErrors.push(error.message));

      const callTimeoutMs = options.callTimeoutMs ?? 15_000;
      await page.goto(pageUrl, { waitUntil: 'domcontentloaded', timeout: callTimeoutMs });
      const outcome = await Promise.race([answered, delay(callTimeoutMs).then(() => 'timeout' as const)]);
      if (outcome === 'timeout') {
        run.error = `the page did not call navigator.credentials.get with a digital credential request within ${callTimeoutMs / 1000} s`;
      } else if (outcome?.kind === 'respond' && outcome.marker) {
        const marker = outcome.marker;
        const deadline = Date.now() + (options.deliveryTimeoutMs ?? 15_000);
        while (Date.now() < deadline) {
          run.delivery = [...exchanges.values()].find((e) => e.postData?.includes(marker) && (e.status !== undefined || e.error !== undefined));
          if (run.delivery) break;
          await delay(50);
        }
        if (!run.delivery) run.error = 'the page did not forward the response to the Relying Party, or received no answer';
        // A moment for the body of the answer, which the page may read or not.
        else if (run.delivery.status !== undefined) await waitFor(() => run.delivery?.body !== undefined, 1000);
      }
    } catch (error) {
      run.error = (error as Error).message.split('\n')[0];
    } finally {
      // The delivery keeps its whole body; the other requests are cut.
      run.network = [...exchanges.values()].map((e) => (e === run.delivery ? { ...e } : { ...e, postData: cut(e.postData) }));
      await context.close().catch(() => {});
    }
    return run;
  }
}

const delay = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

async function waitFor(condition: () => boolean, ms: number) {
  const deadline = Date.now() + ms;
  while (!condition() && Date.now() < deadline) await delay(25);
}
