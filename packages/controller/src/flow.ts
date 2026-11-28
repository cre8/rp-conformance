// The flow steps of catalogue scenario SCN-F (`RP_WS_IA_ProtocolFlow`): steps that continue the transaction of an
// earlier step (its `request_uri` again, its Authorization Response again, its `redirect_uri` in a user agent), the
// wallet's error response, and the expectation codes that read what the Relying Party answered there.
import { randomInt } from 'node:crypto';
import type {
  DefaultQueryId,
  ErrorResponseAction,
  Expectation,
  Flow,
  FlowAction,
  FlowExpectationCode,
  FrontEndResult,
  RelyingPartyAdapter,
  RelyingPartyResult,
  StepDefinition,
} from '@eudi-pcaf/core';
import { FLOW_EXPECTATION_CODES } from '@eudi-pcaf/core';
import type { DcApiOutcome, DcApiShim } from '@eudi-pcaf/dc-api-shim';
import type { ConformanceWallet, DcApiAnswer, HttpExchange, PresentationEvidence } from '@eudi-pcaf/wallet';
import { type Evaluation, evaluateReject, worst } from './evaluate';
import type { StepRecord } from './runner';

/** What the harness keeps of a step's transaction, for the steps that continue it. */
export interface TransactionTrace {
  transactionId: string;
  query: DefaultQueryId;
  /** The invocation URI (redirects) or the page (DC API). */
  invocationUri: string;
  /** Via redirects: where the Authorization Response was posted, the form, and how the Relying Party answered. */
  responseUri?: string;
  responseForm?: Record<string, string>;
  response?: HttpExchange;
  /** Via redirects: the `redirect_uri` of the Relying Party's answer, if any. */
  redirectUri?: string;
  /** The verification result after the step. */
  result?: RelyingPartyResult;
}

/** What the flow steps need from the run. */
export interface FlowContext {
  adapter: RelyingPartyAdapter;
  wallet: ConformanceWallet;
  namespace: string;
  resultTimeoutMs?: number;
  dcApiShim: () => Promise<DcApiShim>;
}

type Save = (name: string, content: string | Uint8Array | undefined) => Promise<void>;

/** Whether a code is evaluated here rather than by `evaluate`. */
export const isFlowCode = (code: string): code is FlowExpectationCode => (FLOW_EXPECTATION_CODES as readonly string[]).includes(code);

/** The expectation without the flow codes, for `evaluate`. */
export const withoutFlowCodes = (expectation: Expectation): Expectation => ({ ...expectation, codes: expectation.codes.filter((c) => !isFlowCode(c)) });

/** The `redirect_uri` of a `response_uri` answer, if it is JSON with one. */
export function redirectUriOf(body: string | undefined): string | undefined {
  try {
    const value = (JSON.parse(body ?? '') as { redirect_uri?: unknown }).redirect_uri;
    return typeof value === 'string' ? value : undefined;
  } catch {
    return undefined;
  }
}

/** The response code of a `redirect_uri`: its `response_code` parameter in the query or the fragment. */
export function responseCodeOf(redirectUri: string | undefined): string | undefined {
  if (!redirectUri) return undefined;
  try {
    const url = new URL(redirectUri);
    return url.searchParams.get('response_code') ?? new URLSearchParams(url.hash.replace(/^#/, '')).get('response_code') ?? undefined;
  } catch {
    return undefined;
  }
}

const isJson = (contentType: string | null | undefined) => contentType?.split(';')[0]?.trim().toLowerCase() === 'application/json';
/** At least 128 bits from a base64url alphabet, as the request checks read `nonce` and `state`. */
const strongRandom = (value: string | undefined) => typeof value === 'string' && /^[A-Za-z0-9_.~-]{22,}$/.test(value);
/** A compact JWS or JWE: what a request object looks like. */
const looksLikeRequestObject = (body: string | undefined) => /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*(\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*)?$/.test((body ?? '').trim());

const flatten = (value: unknown, prefix = ''): Record<string, unknown> => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return prefix ? { [prefix]: value } : {};
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([k, v]) => Object.entries(flatten(v, prefix ? `${prefix}.${k}` : k))));
};
const sameAttributes = (a: Record<string, unknown> | undefined, b: Record<string, unknown> | undefined) => {
  const left = flatten(a ?? {});
  const right = flatten(b ?? {});
  return Object.keys(left).length === Object.keys(right).length && Object.entries(left).every(([k, v]) => JSON.stringify(right[k]) === JSON.stringify(v));
};

/** Inputs of the flow codes, gathered by the step that evaluates them. */
export interface FlowEvaluationInput {
  /** The Relying Party's answer at `response_uri` (redirects). */
  response?: HttpExchange;
  /** The answer at `request_uri` (REQUEST_REFUSED). */
  requestFetch?: HttpExchange;
  /** What the front end released (RELEASED, WITHHELD). */
  frontEnd?: FrontEndResult;
  /** The transaction the step continues, or the step's own (REDIRECT, RESEND_REJ). */
  trace?: TransactionTrace;
  /** The verification result after the step (RESEND_REJ). */
  result?: RelyingPartyResult;
  /** The traces of the earlier steps, for the freshness of the response code (REDIRECT). */
  earlier: TransactionTrace[];
}

/** `REDIRECT`: HTTP 200 `application/json` with a `redirect_uri` carrying a fresh response code of at least 128 bits. */
function evaluateRedirect(input: FlowEvaluationInput): Evaluation {
  const response = input.response;
  if (response?.status === undefined) return { verdict: 'INCONCLUSIVE', reason: 'the Authorization Response was not delivered' };
  if (response.status !== 200) return { verdict: 'FAIL', reason: `response_uri answered HTTP ${response.status}, not 200` };
  if (!isJson(response.contentType)) return { verdict: 'FAIL', reason: `response_uri answered with Content-Type ${String(response.contentType)}, not application/json` };
  const redirectUri = redirectUriOf(response.body);
  if (!redirectUri) return { verdict: 'FAIL', reason: 'the answer of response_uri carries no redirect_uri' };
  const code = responseCodeOf(redirectUri);
  if (!code) return { verdict: 'FAIL', reason: `the redirect_uri ${redirectUri} carries no response_code` };
  if (!strongRandom(code)) return { verdict: 'FAIL', reason: `the response_code ${code} is not a random value of at least 128 bits` };
  const reused = input.earlier.find((t) => responseCodeOf(t.redirectUri) === code);
  if (reused) return { verdict: 'FAIL', reason: `the response_code repeats that of transaction ${reused.transactionId}` };
  return { verdict: 'PASS', reason: `response_uri answered HTTP 200 application/json with a redirect_uri carrying a fresh response_code of ${code.length} characters` };
}

function evaluateCode(code: FlowExpectationCode, input: FlowEvaluationInput): Evaluation {
  switch (code) {
    case 'REDIRECT':
      return evaluateRedirect(input);
    case 'RELEASED': {
      const frontEnd = input.frontEnd;
      if (!frontEnd) return { verdict: 'INCONCLUSIVE', reason: 'the front end was not reached' };
      if (!frontEnd.released) return { verdict: 'FAIL', reason: `the front end released nothing (HTTP ${String(frontEnd.status)})` };
      const expected = input.trace?.result?.releasedAttributes;
      if (expected && !sameAttributes(frontEnd.attributes, expected)) return { verdict: 'FAIL', reason: 'the front end released other attributes than the verification result' };
      return { verdict: 'PASS', reason: `the front end released ${Object.keys(flatten(frontEnd.attributes ?? {})).join(', ') || 'the result'}` };
    }
    case 'WITHHELD': {
      const frontEnd = input.frontEnd;
      if (!frontEnd) return { verdict: 'INCONCLUSIVE', reason: 'the front end was not reached' };
      if (frontEnd.status !== undefined && frontEnd.status >= 500) return { verdict: 'FAIL', reason: `the front end answered HTTP ${frontEnd.status}` };
      if (frontEnd.released || Object.keys(frontEnd.attributes ?? {}).length) return { verdict: 'FAIL', reason: 'the front end released the attributes of the transaction' };
      return { verdict: 'PASS', reason: `the front end released nothing (HTTP ${String(frontEnd.status)})` };
    }
    case 'REQUEST_REFUSED': {
      const fetched = input.requestFetch;
      if (!fetched || fetched.status === undefined) return { verdict: 'INCONCLUSIVE', reason: `request_uri could not be retrieved: ${fetched?.error ?? 'no answer'}` };
      if (fetched.status < 400 || fetched.status >= 500) return { verdict: 'FAIL', reason: `request_uri answered HTTP ${fetched.status}, not 4xx` };
      if (looksLikeRequestObject(fetched.body)) return { verdict: 'FAIL', reason: `request_uri answered HTTP ${fetched.status} with a request object` };
      return { verdict: 'PASS', reason: `request_uri answered HTTP ${fetched.status} without a request object` };
    }
    case 'ERROR_ACK': {
      const response = input.response;
      if (response?.status === undefined) return { verdict: 'INCONCLUSIVE', reason: 'the error response was not delivered' };
      if (response.status !== 200) return { verdict: 'FAIL', reason: `response_uri answered the error response with HTTP ${response.status}, not 200` };
      if (!isJson(response.contentType)) return { verdict: 'FAIL', reason: `response_uri answered with Content-Type ${String(response.contentType)}, not application/json` };
      return { verdict: 'PASS', reason: 'response_uri answered the error response with HTTP 200 application/json' };
    }
    case 'RESEND_REJ': {
      const response = input.response;
      if (response?.status === undefined) return { verdict: 'INCONCLUSIVE', reason: 'the second Authorization Response was not delivered' };
      if (response.status < 400 || response.status >= 500) return { verdict: 'FAIL', reason: `response_uri answered the second Authorization Response with HTTP ${response.status}, not 4xx` };
      const first = input.trace?.result;
      const now = input.result;
      if (!first || !now) return { verdict: 'INCONCLUSIVE', reason: 'the verification result was not read' };
      if (now.outcome !== first.outcome || !sameAttributes(now.releasedAttributes, first.releasedAttributes)) {
        return { verdict: 'FAIL', reason: `the verification result changed from ${first.outcome} to ${now.outcome}` };
      }
      return { verdict: 'PASS', reason: `rejected with HTTP ${response.status}; the verification result is unchanged (${now.outcome})` };
    }
  }
}

/** Evaluates the flow codes of an expectation; `undefined` when it has none. */
export function evaluateFlowCodes(expectation: Expectation, input: FlowEvaluationInput): Evaluation | undefined {
  const codes = expectation.codes.filter(isFlowCode);
  if (!codes.length) return undefined;
  const evaluations = codes.map((code) => evaluateCode(code, input));
  return { verdict: worst(evaluations.map((e) => e.verdict)), reason: evaluations.map((e) => e.reason).join('; ') };
}

/** Combines the evaluation of the other codes with that of the flow codes. */
export function combine(...evaluations: (Evaluation | undefined)[]): Evaluation {
  const present = evaluations.filter((e): e is Evaluation => Boolean(e));
  return { verdict: worst(present.map((e) => e.verdict)), reason: present.map((e) => e.reason).filter(Boolean).join('; ') };
}

/**
 * A `request_uri` of an unknown transaction: the parts in which the `request_uri`s of two transactions differ (path
 * segments, query values) replaced by random values of the same shape.
 */
export function unknownRequestUri(known: string, other: string): string {
  const a = new URL(known);
  const b = new URL(other);
  const segmentsA = a.pathname.split('/');
  const segmentsB = b.pathname.split('/');
  let changed = false;
  const path = segmentsA.map((segment, i) => {
    if (segmentsB[i] === undefined || segmentsB[i] === segment || !segment) return segment;
    changed = true;
    return reshape(segment);
  });
  a.pathname = path.join('/');
  for (const [key, value] of [...a.searchParams]) {
    if (b.searchParams.get(key) !== value) {
      a.searchParams.set(key, reshape(value));
      changed = true;
    }
  }
  if (!changed || a.href === known || a.href === other) throw new Error(`the request_uris of two transactions do not differ (${known})`);
  return a.href;
}

/** A random value of the same shape: each digit, lowercase and uppercase letter replaced by one of its kind. */
function reshape(value: string): string {
  const pick = (alphabet: string) => alphabet[randomInt(alphabet.length)];
  const hex = /^[0-9a-f-]+$/.test(value);
  return [...value]
    .map((c) => {
      if (/[0-9]/.test(c)) return pick(hex ? '0123456789abcdef' : '0123456789');
      if (/[a-z]/.test(c)) return pick(hex ? '0123456789abcdef' : 'abcdefghijklmnopqrstuvwxyz');
      if (/[A-Z]/.test(c)) return pick('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
      return c;
    })
    .join('');
}

/** A `redirect_uri` with a random response code of the same shape instead of the Relying Party's. */
export function forgedRedirectUri(redirectUri: string): string {
  const url = new URL(redirectUri);
  const code = url.searchParams.get('response_code');
  if (code) {
    url.searchParams.set('response_code', reshape(code));
    return url.href;
  }
  const fragment = new URLSearchParams(url.hash.replace(/^#/, ''));
  const inFragment = fragment.get('response_code');
  if (!inFragment) throw new Error(`the redirect_uri ${redirectUri} carries no response_code`);
  fragment.set('response_code', reshape(inFragment));
  url.hash = fragment.toString();
  return url.href;
}

/**
 * Continues the transaction of an earlier step (`FlowAction`) and evaluates the step's codes: the `request_uri`
 * again or of an unknown transaction, the Authorization Response again, or the Relying Party's front end.
 */
export async function runFlow(
  step: StepDefinition,
  action: FlowAction,
  flow: Flow,
  record: StepRecord,
  save: Save,
  ctx: FlowContext,
  traces: Map<number, TransactionTrace>,
): Promise<void> {
  const trace = traces.get(action.ofStep);
  if (!trace) throw new Error(`step ${action.ofStep} recorded no transaction`);
  record.transactionId = trace.transactionId;
  const earlier = [...traces.values()];
  let input: FlowEvaluationInput = { trace, earlier };
  switch (action.behaviour) {
    case 'request-uri-again': {
      const fetched = await ctx.wallet.fetchRequestUri(trace.invocationUri);
      await save('request-uri.json', JSON.stringify(fetched, null, 2));
      record.wallet = { findings: [], requestFetch: { url: fetched.url, status: fetched.status } };
      input = { ...input, requestFetch: fetched };
      break;
    }
    case 'request-uri-unknown': {
      // A second transaction shows which parts of the request_uri identify the transaction.
      const started = await ctx.adapter.startPresentation({ query: trace.query, flow, namespace: ctx.namespace });
      if (!('uri' in started.invocation)) throw new Error('the adapter returned no invocation URI for the redirect flow');
      const known = new URL(trace.invocationUri).searchParams.get('request_uri');
      const other = new URL(started.invocation.uri).searchParams.get('request_uri');
      if (!known || !other) throw new Error('the invocation URI carries no request_uri');
      const unknown = unknownRequestUri(known, other);
      const fetched = await ctx.wallet.fetchRequestUri(unknown);
      await save('request-uri.json', JSON.stringify({ known, other, unknown, fetched }, null, 2));
      record.wallet = { findings: [], requestFetch: { url: fetched.url, status: fetched.status } };
      input = { ...input, requestFetch: fetched };
      break;
    }
    case 'resend': {
      if (!trace.responseUri || !trace.responseForm) throw new Error(`step ${action.ofStep} posted no Authorization Response`);
      const exchange: HttpExchange = { method: 'POST', url: trace.responseUri };
      const response = await fetch(trace.responseUri, { method: 'POST', body: new URLSearchParams(trace.responseForm) });
      exchange.status = response.status;
      exchange.contentType = response.headers.get('content-type');
      exchange.body = await response.text();
      record.rpResponse = { endpoint: 'response_uri', url: exchange.url, status: exchange.status, body: exchange.body };
      const result = await ctx.adapter.readResult(trace.transactionId, ctx.resultTimeoutMs ?? 15_000);
      record.rpResult = result;
      await save('rp-result.json', JSON.stringify(result.raw, null, 2));
      input = { ...input, response: exchange, result };
      break;
    }
    case 'front-end':
    case 'redirect-same':
    case 'redirect-fresh':
    case 'redirect-forged': {
      if (!ctx.adapter.frontEnd) throw new Error(`the ${ctx.adapter.name} adapter does not drive the Relying Party's front end (ICS RP.P.9)`);
      let url: string | undefined;
      if (action.behaviour !== 'front-end') {
        if (!trace.redirectUri) throw new Error(`the Relying Party returned no redirect_uri in step ${action.ofStep}`);
        url = action.behaviour === 'redirect-forged' ? forgedRedirectUri(trace.redirectUri) : trace.redirectUri;
      }
      const frontEnd = await ctx.adapter.frontEnd({ transactionId: trace.transactionId, url, userAgent: action.behaviour === 'redirect-fresh' ? 'fresh' : 'same' });
      await save('front-end.json', JSON.stringify({ url: url ?? null, userAgent: action.behaviour === 'redirect-fresh' ? 'fresh' : 'same', ...frontEnd }, null, 2));
      input = { ...input, frontEnd };
      break;
    }
  }
  const evaluation = evaluateFlowCodes(step.expect, input) ?? { verdict: 'INCONCLUSIVE' as const, reason: 'a flow step evaluates flow codes only' };
  const other = step.expect.codes.filter((c) => !isFlowCode(c));
  record.verdict = other.length ? 'INCONCLUSIVE' : evaluation.verdict;
  record.reason = other.length ? `a flow step does not evaluate ${other.join(', ')}` : evaluation.reason;
}

/**
 * Starts a presentation and answers it with the wallet's error response: unencrypted to `response_uri` via redirects,
 * an error object through the DC API. Evaluates `REJ` (the transaction ends as failed) and, via redirects,
 * `ERROR_ACK`.
 */
export async function runErrorResponse(
  step: StepDefinition,
  action: ErrorResponseAction,
  flow: Flow,
  record: StepRecord,
  save: Save,
  ctx: FlowContext,
  start: () => Promise<{ transactionId: string; uri: string }>,
): Promise<void> {
  const { transactionId, uri } = await start();
  let evidence: PresentationEvidence;
  let delivered: boolean;
  let response: HttpExchange | undefined;
  if (flow === 'dc-api') {
    let walletEvidence: PresentationEvidence | undefined;
    let answer: DcApiAnswer | undefined;
    const run = await (await ctx.dcApiShim()).run(uri, async (call): Promise<DcApiOutcome> => {
      ({ evidence: walletEvidence, answer } = await ctx.wallet.respondWithErrorDcApi(call, action.error));
      if (!answer) return { kind: 'respond', protocol: call.requests[0]?.protocol ?? '', data: { error: 'invalid_request', error_description: walletEvidence.error } };
      return { kind: 'respond', ...answer, marker: `"error":"${action.error}"` };
    });
    evidence = walletEvidence ?? { invocationUri: uri, findings: [], error: run.error ?? 'the page made no digital credential request' };
    await save('dc-api-run.json', JSON.stringify(run, null, 2));
    record.dcApi = { page: run.pageUrl, origin: run.calls[0]?.origin, protocol: evidence.dcApi?.protocol, ...(run.error ? { error: run.error } : {}) };
    delivered = Boolean(answer) && run.calls.length > 0;
    if (run.delivery) {
      record.rpResponse = { endpoint: 'dc-api-forward', url: run.delivery.url, status: run.delivery.status, body: run.delivery.body };
      response = { method: run.delivery.method, url: run.delivery.url, status: run.delivery.status, contentType: run.delivery.contentType, body: run.delivery.body };
    }
  } else {
    evidence = await ctx.wallet.respondWithError(uri, action.error);
    await save('request.jwt', evidence.requestFetch?.body);
    await save('response.form.json', evidence.responseForm && JSON.stringify(evidence.responseForm, null, 2));
    response = evidence.response;
    delivered = response?.status !== undefined;
    if (response) record.rpResponse = { endpoint: 'response_uri', url: response.url, status: response.status, body: response.body };
  }
  await save('wallet-evidence.json', JSON.stringify(evidence, null, 2));
  record.wallet = { findings: evidence.findings, error: evidence.error, requestFetch: evidence.requestFetch && { url: evidence.requestFetch.url, status: evidence.requestFetch.status } };
  const result = await ctx.adapter.readResult(transactionId, ctx.resultTimeoutMs ?? 15_000);
  record.rpResult = result;
  await save('rp-result.json', JSON.stringify(result.raw, null, 2));
  const evaluations = step.expect.codes.map((code): Evaluation => {
    if (code === 'REJ') return evaluateReject(result, response?.status, delivered);
    if (code === 'ERROR_ACK') return evaluateCode(code, { response, earlier: [] });
    return { verdict: 'INCONCLUSIVE', reason: `expected result ${code} does not apply to an error response` };
  });
  const evaluation = combine(...evaluations);
  record.verdict = evaluation.verdict;
  record.reason = evidence.error && evaluation.verdict !== 'PASS' ? `${evaluation.reason}; Conformance Wallet: ${evidence.error}` : evaluation.reason;
}
