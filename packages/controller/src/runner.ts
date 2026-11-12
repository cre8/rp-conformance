import { randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import {
  categoryOfQuery,
  FLOWS,
  type Flow,
  faultsOf,
  flowIcsItems,
  flowsOf,
  type Ics,
  isExecutable,
  type PresentationAction,
  type RelyingPartyAdapter,
  type RelyingPartyResult,
  type StartAction,
  type StepDefinition,
  type TestCaseDefinition,
  type TrustListAction,
  type Verdict,
  controlsOf,
} from '@rp-conformance/core';
import { base64url, defaultEntitiesOf, forgePresentation } from '@rp-conformance/forge';
import { DcApiShim, type DcApiOutcome, type DcApiRun } from '@rp-conformance/dc-api-shim';
import { ConformanceWallet, type DcApiAnswer, type HeldCredential, type PresentationEvidence } from '@rp-conformance/wallet';
import { evaluate, worst } from './evaluate';
import { type Harness, startHarness } from './harness';
import { applicability, icsAnswer } from './ics';
import { harnessInfo } from './info';
import { writeSummary } from './summary';

/** The flows the harness implements: redirects, and the W3C Digital Credentials API through the DC API shim. */
export const IMPLEMENTED_FLOWS: Flow[] = FLOWS;

export interface StepRecord {
  step: number;
  /** `presentation`, `start` (request only) or `trust-list` (new list version). */
  action: string;
  text: string;
  /** Expected-result codes, for example `ACC` or `REJ + NOFETCH`. */
  expected: string;
  expectedResult: string;
  /** The named fault of the step, `null` for valid material. */
  fault: string | null;
  transactionId?: string;
  /**
   * Where the Relying Party received the Authorization Response and how it answered: its `response_uri` (redirects),
   * or the request in which its page forwarded the response the DC API returned (`dc-api-forward`).
   */
  rpResponse?: { endpoint: 'response_uri' | 'dc-api-forward'; url: string; status?: number; body?: string };
  /** Via the DC API: the page, the Origin the shim saw, the protocol the wallet answered, and what went wrong. */
  dcApi?: { page: string; origin?: string; protocol?: string; error?: string; pageErrors?: string[] };
  rpResult?: RelyingPartyResult;
  wallet?: {
    findings: PresentationEvidence['findings'];
    error?: string;
    redirect?: PresentationEvidence['redirect'];
    requestFetch?: { url: string; status?: number };
  };
  statusLog: { url: string; at: string; status: number }[];
  trustLog?: { url: string; at: string; status: number; version?: number }[];
  artifacts: string[];
  verdict: Verdict;
  reason: string;
}

export interface TestCaseRecord {
  testCase: string;
  flow: Flow;
  verdict: Verdict;
  reason?: string;
  /** The positive control this verdict depends on; `null` for a positive control. */
  control: { id: string; verdict: Verdict } | null;
  steps: StepRecord[];
}

export interface RunReport {
  run: {
    id: string;
    startedAt: string;
    finishedAt?: string;
    adapter: string;
    flows: Flow[];
    ics: Ics;
    harness: ReturnType<typeof harnessInfo>;
    environment: {
      namespace: string;
      statusProvider: string;
      trustInfrastructure: string;
      trustLists: { id: string; url: string }[];
      listOfTrustedLists: { url: string; pointers: { id: string; url: string }[] };
    };
    summary: Partial<Record<Verdict, number>>;
    /** Why the run could not execute its test cases, if it could not. */
    error?: string;
  };
  results: TestCaseRecord[];
}

export interface RunOptions {
  adapter: RelyingPartyAdapter;
  ics: Ics;
  definitions: TestCaseDefinition[];
  /** Test case IDs or patterns with `*`. */
  only?: string[];
  flows?: Flow[];
  reportDir: string;
  /** Host name under which the Relying Party reaches the harness services. */
  harnessHost: string;
  /** Milliseconds to wait for the verification result. */
  resultTimeoutMs?: number;
  /**
   * Milliseconds to wait for the Relying Party to retrieve a new trust list version after the adapter's refresh hook,
   * before the retrieval is checked again after the next step; default 10 s, or `T_refresh` without a hook.
   */
  trustRefreshWaitMs?: number;
  log?: (line: string) => void;
}

const matches = (id: string, pattern: string) =>
  new RegExp(`^${pattern.split('*').map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`).test(id);

/**
 * Selects the executable test cases and adds the positive controls they depend on, controls first (harness design
 * section 4.1). Text-only definitions are left out.
 */
export function selectTestCases(all: TestCaseDefinition[], only?: string[]): TestCaseDefinition[] {
  const definitions = all.filter(isExecutable);
  const selected = only?.length ? definitions.filter((d) => only.some((p) => matches(d.id, p))) : [...definitions];
  if (only?.length && selected.length === 0) {
    const textOnly = all.filter((d) => !isExecutable(d) && only.some((p) => matches(d.id, p)));
    throw new Error(`no executable test case matches ${only.join(', ')}${textOnly.length ? ` (text only: ${textOnly.map((d) => d.id).join(', ')})` : ''}`);
  }
  for (const definition of [...selected]) {
    const ids = controlsOf(definition);
    const controls = definitions.filter((d) => ids.includes(d.id));
    if (ids.length && controls.length === 0) throw new Error(`${definition.id}: control ${ids.join(' or ')} has no definition`);
    for (const control of controls) if (!selected.includes(control)) selected.push(control);
  }
  return [...selected.filter((d) => !d.control), ...selected.filter((d) => d.control)];
}

/** ISO 8601 duration (`PT1H`, `PT5M`, `PT30S`) in milliseconds. */
export function durationMs(value: string | undefined): number | undefined {
  const match = value && /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$/.exec(value);
  if (!match) return undefined;
  const [, d = '0', h = '0', m = '0', s = '0'] = match;
  return ((Number(d) * 24 + Number(h)) * 60 + Number(m)) * 60_000 + Number(s) * 1000;
}

export async function runConformance(options: RunOptions): Promise<{ report: RunReport; reportPath: string }> {
  const log = options.log ?? (() => {});
  const runId = `r${new Date().toISOString().replace(/[-:]/g, '').slice(0, 15)}-${randomBytes(3).toString('hex')}`;
  const runDir = join(options.reportDir, runId);
  const namespace = runId;
  const requestedFlows = options.flows ?? IMPLEMENTED_FLOWS;
  const notImplemented = requestedFlows.filter((f) => !IMPLEMENTED_FLOWS.includes(f));
  if (notImplemented.length) throw new Error(`unknown flow ${notImplemented.join(', ')} (flows: ${IMPLEMENTED_FLOWS.join(', ')})`);
  const flows = requestedFlows.filter((flow) => icsAnswer(options.ics, flowIcsItems[flow]) === 'Yes');

  const harness = await startHarness({ runId, harnessHost: options.harnessHost, namespace, ics: options.ics });
  // The browser of the DC API shim starts with the first DC API step and stays open for the run.
  let shim: Promise<DcApiShim> | undefined;
  const dcApiShim = () => (shim ??= DcApiShim.launch());
  const report: RunReport = {
    run: {
      id: runId,
      startedAt: new Date().toISOString(),
      adapter: options.adapter.name,
      flows,
      ics: options.ics,
      harness: harnessInfo(),
      environment: {
        namespace,
        statusProvider: harness.status.baseUrl,
        trustInfrastructure: harness.trust.baseUrl,
        trustLists: harness.env.trustLists.map(({ id, url }) => ({ id, url })),
        listOfTrustedLists: {
          url: harness.env.listOfTrustedLists.url,
          pointers: harness.env.listOfTrustedLists.pointers.map(({ id, url }) => ({ id, url })),
        },
      },
      summary: {},
    },
    results: [],
  };
  try {
    log(`run ${runId}: harness services at ${harness.status.baseUrl} (status) and ${harness.trust.baseUrl} (trust)`);
    const selected = selectTestCases(options.definitions, options.only);
    try {
      await options.adapter.setUp(harness.env, namespace);
    } catch (error) {
      // Without a configured Relying Party no test case can produce a verdict.
      report.run.error = `adapter set-up failed: ${(error as Error).message}`;
      for (const definition of selected) {
        for (const flow of flowsOf(definition).filter((f) => flows.includes(f))) {
          report.results.push({ testCase: definition.id, flow, verdict: 'INCONCLUSIVE', reason: report.run.error, control: null, steps: [] });
        }
      }
      log(report.run.error);
      return await writeReport(report, runDir);
    }
    log(`adapter ${options.adapter.name} set up`);
    const wallet = await ConformanceWallet.create({
      accessCertificateAnchors: [harness.pki.entities['AC-A'].anchors.issuance.certificate],
      allowInsecureUrls: true,
    });
    for (const definition of selected) {
      // Every test case once per flow, except the SessionEncryption variants, whose profile names their flow.
      for (const flow of flowsOf(definition).filter((f) => requestedFlows.includes(f))) {
        const record = await runTestCase(definition, flow, flows.includes(flow), { ...options, harness, wallet, runDir, report, dcApiShim });
        report.results.push(record);
        log(`${record.verdict.padEnd(14)} ${record.testCase} [${record.flow}]${record.reason ? ` ${record.reason}` : ''}`);
        for (const step of record.steps.filter((s) => s.verdict !== 'PASS')) log(`    step ${step.step} ${step.verdict}: ${step.reason}`);
      }
    }
  } finally {
    await options.adapter.tearDown?.().catch(() => {});
    await shim?.then((s) => s.close()).catch(() => {});
    await harness.stop();
  }
  return writeReport(report, runDir);
}

async function writeReport(report: RunReport, runDir: string): Promise<{ report: RunReport; reportPath: string }> {
  report.run.finishedAt = new Date().toISOString();
  report.run.summary = {};
  for (const result of report.results) report.run.summary[result.verdict] = (report.run.summary[result.verdict] ?? 0) + 1;
  await mkdir(runDir, { recursive: true });
  const reportPath = join(runDir, 'report.json');
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  await writeSummary(report, join(runDir, 'summary.md'));
  return { report, reportPath };
}

interface Context extends RunOptions {
  harness: Harness;
  wallet: ConformanceWallet;
  dcApiShim: () => Promise<DcApiShim>;
  runDir: string;
  report: RunReport;
}

/** State shared by the steps of one test case. */
interface TestCaseState {
  /** The encryption key each step's request carried, by step number. */
  encryptionKeys: Map<number, NonNullable<PresentationEvidence['encryptionKey']>>;
  /** Lists the test case changed, restored afterwards. */
  changedLists: Set<'TL-PID'>;
  /** The current entities of each changed list. */
  entities: Map<'TL-PID', string[]>;
  /** A list retrieval still awaited, checked again after the next step. */
  pendingRetrieval?: { record: StepRecord; list: 'TL-PID'; version: number; publishedAt: Date; checks: number };
  /** Whether the Relying Party answered a request of this test case (a started presentation). */
  rpReached: boolean;
}

async function runTestCase(definition: TestCaseDefinition, flow: Flow, flowSupported: boolean, ctx: Context): Promise<TestCaseRecord> {
  const base = { testCase: definition.id, flow };
  // One passed control is enough when the definition names alternatives (for example 001a or 001b).
  const outcomes = controlsOf(definition).map((id) => ({
    id,
    verdict: ctx.report.results.find((r) => r.testCase === id && r.flow === flow)?.verdict ?? ('INCONCLUSIVE' as Verdict),
  }));
  const control = outcomes.find((o) => o.verdict === 'PASS') ?? outcomes[0] ?? null;
  const end = (verdict: Verdict, reason: string): TestCaseRecord => ({ ...base, verdict, reason, control, steps: [] });
  if (!flowSupported) return end('NOT APPLICABLE', `the ICS does not declare the ${flow} flow`);
  const unmet = applicability(definition, ctx.ics);
  if (unmet.length) return end('NOT APPLICABLE', `profile not met: ${unmet.join('; ')}`);
  if (control && control.verdict !== 'PASS') {
    return end('INCONCLUSIVE', `positive control ${outcomes.map((o) => o.id).join(' or ')} did not pass`);
  }
  const state: TestCaseState = { encryptionKeys: new Map(), changedLists: new Set(), entities: new Map(), rpReached: false };
  const steps: StepRecord[] = [];
  let restoreError: string | undefined;
  try {
    for (const [index, step] of definition.steps.entries()) {
      steps.push(await runStep(definition, flow, index + 1, step, ctx, state));
      await checkPendingRetrieval(state, ctx, false);
    }
    await checkPendingRetrieval(state, ctx, true);
  } finally {
    // Restore the lists the test case changed (comment of TrustMechanisms_007 and _008). A Relying Party that does not
    // answer the refresh leaves the list restored at the Test Trust Infrastructure; the run goes on.
    for (const list of state.changedLists) {
      await ctx.harness.publishList(list);
      await ctx.adapter.refreshTrust?.(ctx.harness.namespace).catch((error: unknown) => {
        restoreError = `restoring ${list}: the trust refresh failed: ${(error as Error).message}`;
      });
    }
  }
  return { ...base, verdict: worst(steps.map((s) => s.verdict)), control, steps, ...(restoreError ? { reason: restoreError } : {}) };
}

/** Whether an error is a failed connection to a server (refused, reset, closed), not a fault of the harness itself. */
function isConnectionError(error: unknown): boolean {
  const codes = ['ECONNREFUSED', 'ECONNRESET', 'EPIPE', 'UND_ERR_SOCKET', 'UND_ERR_CLOSED', 'ETIMEDOUT'];
  for (let current: unknown = error; current; current = (current as { cause?: unknown }).cause) {
    if (codes.includes(String((current as { code?: unknown }).code))) return true;
    if (current instanceof TypeError && current.message === 'fetch failed') return true;
  }
  return false;
}

function newRecord(index: number, step: StepDefinition): StepRecord {
  const action = step.run;
  const faults = action ? faultsOf(action) : [];
  return {
    step: index,
    action: action?.kind ?? 'none',
    text: step.text,
    expected: step.expect.codes.join(' + '),
    expectedResult: step.expect.text,
    fault: faults.length ? faults.join(', ') : null,
    statusLog: [],
    artifacts: [],
    verdict: 'INCONCLUSIVE',
    reason: '',
  };
}

async function runStep(
  definition: TestCaseDefinition,
  flow: Flow,
  index: number,
  step: StepDefinition,
  ctx: Context,
  state: TestCaseState,
): Promise<StepRecord> {
  const record = newRecord(index, step);
  const dir = join(ctx.runDir, 'artifacts', definition.id, flow, `step-${index}`);
  await mkdir(dir, { recursive: true });
  const save = async (name: string, content: string | Uint8Array | undefined) => {
    if (content === undefined) return;
    await writeFile(join(dir, name), content);
    record.artifacts.push(relative(ctx.runDir, join(dir, name)));
  };
  try {
    switch (step.run?.kind) {
      case 'presentation':
        await runPresentation(step, step.run, flow, record, save, ctx, state);
        break;
      case 'start':
        await runStart(step.run, flow, index, record, save, ctx, state);
        break;
      case 'trust-list':
        await runTrustList(step.run, record, ctx, state);
        break;
      default:
        record.reason = 'the step is text only';
    }
  } catch (error) {
    if (state.rpReached && isConnectionError(error)) {
      // The Relying Party answered earlier in this test case and stopped answering: it did not stay available
      // (RP_PP_SM_Revocation_016). A Relying Party unreachable from the start of a test case stays INCONCLUSIVE.
      record.verdict = 'FAIL';
      record.reason = `the Relying Party became unavailable during the test case: ${describeError(error)}`;
    } else {
      record.verdict = 'INCONCLUSIVE';
      record.reason = `the harness could not execute the step: ${describeError(error)}`;
    }
  }
  return record;
}

type Save = (name: string, content: string | Uint8Array | undefined) => Promise<void>;

/** An error message with the code of its cause, for example `fetch failed (ECONNREFUSED)`. */
const describeError = (error: unknown) => {
  const code = (error as { cause?: { code?: string } }).cause?.code;
  return `${(error as Error).message}${code ? ` (${code})` : ''}`;
};

const sameBody = (a: string | Uint8Array, b: string | Uint8Array) =>
  typeof a === 'string' || typeof b === 'string' ? a === b : Buffer.from(a).equals(Buffer.from(b));

/** Starts a presentation at the Relying Party: the invocation URI of the redirect flow, or the page of the DC API flow. */
async function startPresentation(action: { query: PresentationAction['query'] }, flow: Flow, record: StepRecord, save: Save, ctx: Context) {
  const started = await ctx.adapter.startPresentation({ query: action.query, flow, namespace: ctx.harness.namespace });
  record.transactionId = started.transactionId;
  if (flow === 'dc-api') {
    if (!('dcApiPage' in started.invocation)) throw new Error('the adapter returned no page for the DC API flow');
    await save('dc-api-page.txt', started.invocation.dcApiPage);
    return { transactionId: started.transactionId, uri: started.invocation.dcApiPage };
  }
  if (!('uri' in started.invocation)) throw new Error('the adapter returned no invocation URI for the redirect flow');
  await save('invocation.txt', started.invocation.uri);
  return { transactionId: started.transactionId, uri: started.invocation.uri };
}

/**
 * The string by which the shim recognises the page's delivery of the response: the JWE (or the JWS of a fault), or, for
 * an unencrypted response, the presentation up to its first `~`, which survives JSON and form encoding alike.
 */
function deliveryMarker(data: Record<string, unknown>, presentation: string | undefined): string | undefined {
  if (typeof data.response === 'string') return data.response;
  return presentation?.split('~')[0];
}

/** Saves what the DC API shim saw and the request the page passed, and records it on the step. */
async function recordDcApiRun(run: DcApiRun, evidence: PresentationEvidence | undefined, record: StepRecord, save: Save) {
  const signed = run.calls[0]?.requests.find((r) => r.protocol === evidence?.dcApi?.protocol)?.data as { request?: unknown } | undefined;
  await save('request.jwt', typeof signed?.request === 'string' ? signed.request : undefined);
  await save('dc-api-run.json', JSON.stringify(run, null, 2));
  record.dcApi = {
    page: run.pageUrl,
    origin: run.calls[0]?.origin,
    protocol: evidence?.dcApi?.protocol,
    ...(run.error ? { error: run.error } : {}),
    ...(run.pageErrors.length ? { pageErrors: run.pageErrors } : {}),
  };
}

function walletRecord(evidence: PresentationEvidence): StepRecord['wallet'] {
  return {
    findings: evidence.findings,
    error: evidence.error,
    redirect: evidence.redirect,
    requestFetch: evidence.requestFetch && { url: evidence.requestFetch.url, status: evidence.requestFetch.status },
  };
}

async function runPresentation(
  step: StepDefinition,
  action: PresentationAction,
  flow: Flow,
  record: StepRecord,
  save: Save,
  ctx: Context,
  state: TestCaseState,
) {
  const skewSeconds = Number(ctx.ics.items['RP.P.4'] ?? 0);
  // Every credential gets a unique status URL (harness design section 4.6).
  const forged = await forgePresentation(action, {
    pki: ctx.harness.pki,
    holderPublicJwk: ctx.wallet.holderKey.publicJwk,
    allocateStatusUri: () => ctx.harness.status.allocate(ctx.harness.env.runId),
    skewSeconds,
  });
  const mdoc = forged.format === 'mso_mdoc';
  if (forged.statusList) {
    const { served, validToken } = forged.statusList;
    ctx.harness.status.register(forged.statusList.uri, served.body, { contentType: served.contentType });
    const extension = mdoc ? 'cwt' : 'jwt';
    await save(/json|cbor/.test(served.contentType) ? `status-list.${mdoc ? 'cbor' : 'json'}` : `status-list.${extension}`, served.body);
    if (!sameBody(served.body, validToken)) await save(`status-list.valid.${extension}`, validToken);
  }
  if (forged.identifierList) {
    const { served, validToken } = forged.identifierList;
    ctx.harness.status.register(forged.identifierList.uri, served.body, { contentType: served.contentType });
    await save('identifier-list.cwt', served.body);
    if (!sameBody(served.body, validToken)) await save('identifier-list.valid.cwt', validToken);
  }
  await save(mdoc ? 'credential.issuer-signed.cbor' : 'credential.sd-jwt', forged.credential);

  const query = ctx.harness.env.queries[action.query];
  const stepStart = new Date();
  const { transactionId, uri } = await startPresentation(action, flow, record, save, ctx);
  state.rpReached = true;
  const otherKey = action.response.keyOfStep ? state.encryptionKeys.get(action.response.keyOfStep) : undefined;
  if (action.response.keyOfStep && !otherKey) throw new Error(`step ${action.response.keyOfStep} recorded no encryption key`);
  const held: HeldCredential = mdoc
    ? { format: 'mso_mdoc', value: forged.credential as Uint8Array }
    : { format: 'dc+sd-jwt', value: forged.credential as string };
  const responseOptions = { enc: action.response.enc, fault: action.response.faults[0], otherTransactionKey: otherKey };

  let evidence: PresentationEvidence;
  /** Whether the Authorization Response reached the Relying Party: posted to `response_uri`, or returned to its page. */
  let delivered: boolean;
  if (flow === 'dc-api') {
    let walletEvidence: PresentationEvidence | undefined;
    let answer: DcApiAnswer | undefined;
    const run = await (await ctx.dcApiShim()).run(uri, async (call): Promise<DcApiOutcome> => {
      ({ evidence: walletEvidence, answer } = await ctx.wallet.presentDcApi(call, held, responseOptions));
      // A wallet that cannot use the request answers with an OpenID4VP error (Appendix A.4), not a presentation.
      if (!answer) return { kind: 'respond', protocol: call.requests[0]?.protocol ?? '', data: { error: 'invalid_request', error_description: walletEvidence.error } };
      return { kind: 'respond', ...answer, marker: deliveryMarker(answer.data, walletEvidence.presentation) };
    });
    evidence = walletEvidence ?? { invocationUri: uri, findings: [], error: run.error ?? 'the page made no digital credential request' };
    await recordDcApiRun(run, walletEvidence, record, save);
    await save('response.data.json', evidence.responseData && JSON.stringify(evidence.responseData, null, 2));
    delivered = Boolean(answer) && run.calls.length > 0;
    if (run.delivery) {
      record.rpResponse = { endpoint: 'dc-api-forward', url: run.delivery.url, status: run.delivery.status, body: run.delivery.body };
    }
    if (delivered && run.error) evidence.error = evidence.error ?? run.error;
  } else {
    evidence = await ctx.wallet.present(uri, held, responseOptions);
    await save('request.jwt', evidence.requestFetch?.body);
    await save('response.form.json', evidence.responseForm && JSON.stringify(evidence.responseForm, null, 2));
    delivered = evidence.response?.status !== undefined;
    if (evidence.response) {
      record.rpResponse = { endpoint: 'response_uri', url: evidence.response.url, status: evidence.response.status, body: evidence.response.body };
    }
  }
  if (evidence.encryptionKey) state.encryptionKeys.set(record.step, evidence.encryptionKey);
  await save(mdoc ? 'presentation.device-response.cbor' : 'presentation.sd-jwt', mdoc && evidence.presentation ? base64url.decode(evidence.presentation) : evidence.presentation);
  await save('wallet-evidence.json', JSON.stringify(evidence, null, 2));
  record.wallet = walletRecord(evidence);

  record.rpResult = await ctx.adapter.readResult(transactionId, ctx.resultTimeoutMs ?? 15_000);
  await save('rp-result.json', JSON.stringify(record.rpResult.raw, null, 2));
  // The status list or identifier list the credential references; `FETCHED` and `NOFETCH` read its log.
  const listUri = forged.statusList?.uri ?? forged.identifierList?.uri;
  record.statusLog = listUri ? ctx.harness.status.requestsFor(listUri, stepStart).map(({ url, at, status }) => ({ url, at, status })) : [];

  const evaluation = evaluate(step.expect, {
    result: record.rpResult,
    query,
    issuedClaims: forged.claims,
    delivered,
    responseStatus: record.rpResponse?.status,
    ics: ctx.ics,
    category: categoryOfQuery(action.query),
    statusRequests: record.statusLog.length,
  });
  record.verdict = evaluation.verdict;
  record.reason = evidence.error && evaluation.verdict !== 'PASS' ? `${evaluation.reason}; Conformance Wallet: ${evidence.error}` : evaluation.reason;
}

/**
 * Starts a presentation and records the encryption key of its request without answering (`ENC_KEY`). Via the DC API the
 * wallet resolves the request the page passed and the shim leaves the page's promise pending.
 */
async function runStart(action: StartAction, flow: Flow, index: number, record: StepRecord, save: Save, ctx: Context, state: TestCaseState) {
  const { uri } = await startPresentation(action, flow, record, save, ctx);
  state.rpReached = true;
  let evidence: PresentationEvidence;
  if (flow === 'dc-api') {
    let walletEvidence: PresentationEvidence | undefined;
    const run = await (await ctx.dcApiShim()).run(uri, async (call): Promise<DcApiOutcome> => {
      walletEvidence = await ctx.wallet.startDcApi(call);
      return { kind: 'withhold' };
    });
    evidence = walletEvidence ?? { invocationUri: uri, findings: [], error: run.error ?? 'the page made no digital credential request' };
    await recordDcApiRun(run, walletEvidence, record, save);
  } else {
    evidence = await ctx.wallet.start(uri);
    await save('request.jwt', evidence.requestFetch?.body);
  }
  await save('wallet-evidence.json', JSON.stringify(evidence, null, 2));
  record.wallet = walletRecord(evidence);
  if (evidence.encryptionKey) {
    state.encryptionKeys.set(index, evidence.encryptionKey);
    record.verdict = 'PASS';
    record.reason = `the request carries the encryption key ${evidence.encryptionKey.kid ?? '(no kid)'}`;
  } else {
    record.verdict = evidence.error ? 'INCONCLUSIVE' : 'FAIL';
    record.reason = evidence.error ? `the request could not be resolved: ${evidence.error}` : 'the request carries no encryption key in client_metadata';
  }
}

/**
 * Publishes a new version of a list, asks the adapter to refresh, and waits until the Relying Party retrieved it
 * (`LIST_RETRIEVED`). A Relying Party that fetches lists only when it needs them retrieves the new version during the
 * next step, so a retrieval missing at the end of the wait is checked again after that step.
 */
async function runTrustList(action: TrustListAction, record: StepRecord, ctx: Context, state: TestCaseState) {
  const current = state.entities.get(action.list) ?? defaultEntitiesOf(ctx.harness.pki, action.list);
  const entities = [...current.filter((e) => !action.remove?.includes(e)), ...(action.add ?? []).filter((e) => !current.includes(e))];
  state.entities.set(action.list, entities);
  state.changedLists.add(action.list);
  const { version, publishedAt } = await ctx.harness.publishList(action.list, entities);
  record.reason = `published version ${version} of ${action.list} with ${entities.join(', ')}`;
  await ctx.adapter.refreshTrust?.(ctx.harness.namespace);
  const refreshMs = durationMs(String(ctx.ics.items['RP.T.1'] ?? '')) ?? 60_000;
  const waitMs = ctx.trustRefreshWaitMs ?? (ctx.adapter.refreshTrust ? 10_000 : refreshMs);
  const deadline = Date.now() + waitMs;
  state.pendingRetrieval = { record, list: action.list, version, publishedAt, checks: 0 };
  while (Date.now() < deadline) {
    if (retrievals(state, ctx).length) break;
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
}

function retrievals(state: TestCaseState, ctx: Context) {
  const pending = state.pendingRetrieval;
  if (!pending) return [];
  return ctx.harness.trust
    .retrievalsOf(ctx.harness.namespace, pending.list, pending.publishedAt)
    .filter((entry) => entry.status === 200 && (entry.version ?? 0) >= pending.version);
}

/** Evaluates `LIST_RETRIEVED` right after the trust-list step and, if needed, once more after the next step. */
async function checkPendingRetrieval(state: TestCaseState, ctx: Context, final: boolean) {
  const pending = state.pendingRetrieval;
  if (!pending) return;
  const found = retrievals(state, ctx);
  pending.record.trustLog = found.map(({ url, at, status, version }) => ({ url, at, status, version }));
  pending.checks += 1;
  if (found.length) {
    pending.record.verdict = 'PASS';
    pending.record.reason += `; the Relying Party retrieved it at ${found[0].at}`;
    state.pendingRetrieval = undefined;
  } else if (final || pending.checks >= 2) {
    pending.record.verdict = 'FAIL';
    pending.record.reason += '; the Relying Party did not retrieve it';
    state.pendingRetrieval = undefined;
  }
}
