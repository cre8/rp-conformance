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
  type CapturedRequest,
  type CheckResult,
  type PresentationAction,
  type RequestAction,
  type PublishableList,
  type RelyingPartyAdapter,
  type RelyingPartyResult,
  type StartAction,
  type StepDefinition,
  type TestBookItem,
  type TestCaseDefinition,
  type TrustListAction,
  type Verdict,
  controlsOf,
  durationMs,
} from '@eudi-pcaf/core';
import { base64url, credentialQueryOf, defaultEntitiesOf, forgePresentations, heldCredentialOf, requestAnchorKeyIds, trustedListEntitiesOf } from '@eudi-pcaf/forge';
import { DcApiShim, type DcApiOutcome, type DcApiRun } from '@eudi-pcaf/dc-api-shim';
import { validateRequests } from '@eudi-pcaf/validator';
import { ConformanceWallet, type DcApiAnswer, type HeldCredential, type PresentationEvidence } from '@eudi-pcaf/wallet';
import { evaluate, worst } from './evaluate';
import { type Harness, startHarness } from './harness';
import { applicability, icsAnswer } from './ics';
import { harnessInfo } from './info';
import { writeJUnit } from './junit';
import { describeFinding, type KnownFinding, knownFindingOf } from './known-findings';
import { writeSummary } from './summary';
import { isServed, presetStatusUri, servedAs } from './status-endpoint';
import { combine, evaluateFlowCodes, redirectUriOf, runErrorResponse, runFlow, type TransactionTrace, withoutFlowCodes } from './flow';

/** The flows the harness implements: redirects, and the W3C Digital Credentials API through the DC API shim. */
export const IMPLEMENTED_FLOWS: Flow[] = FLOWS;

export interface StepRecord {
  step: number;
  /** `presentation`, `start` (request only), `trust-list` (new list version) or `request` (requests checked). */
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
  statusLog: { url: string; at: string; status: number; method?: string; target?: string; headers?: Record<string, unknown> }[];
  trustLog?: { url: string; at: string; status: number; version?: number }[];
  /** A request step: the request checks over the captured requests. */
  requestChecks?: CheckResult[];
  artifacts: string[];
  verdict: Verdict;
  reason: string;
}

export interface TestCaseRecord {
  testCase: string;
  flow: Flow;
  verdict: Verdict;
  reason?: string;
  /** For a FAIL that is a known finding of the Relying Party under test: the finding and where it is tracked. */
  knownFinding?: string;
  durationMs?: number;
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
    /** What the adapter reports about the Relying Party under test, for example its version and commit. */
    rp?: Record<string, string>;
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
  /** The selected test book items, each REVIEW with its method: inspections the harness cannot execute. */
  testBook?: TestBookRecord[];
}

/** A test book item in the report: always REVIEW, with the method of the inspection. */
export interface TestBookRecord extends TestBookItem {
  verdict: 'REVIEW';
}

export interface RunOptions {
  adapter: RelyingPartyAdapter;
  ics: Ics;
  definitions: TestCaseDefinition[];
  /** The test book items, reported as REVIEW (`only` selects them like test cases). */
  testBook?: TestBookItem[];
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
  /** Known findings of the Relying Party under test; a FAIL that matches one is marked in the report. */
  knownFindings?: KnownFinding[];
  /**
   * How many test case runs execute at a time (harness design section 6); default 1, every run one after another in
   * definition order. With more, the runs that change the trust lists of the namespace run after the others, one at a
   * time. The report lists the results in definition order either way.
   */
  concurrency?: number;
  log?: (line: string) => void;
}

/**
 * Whether a test case publishes new trust list versions in the run's namespace (a `trust-list` step). Every other test
 * case relies on the default trust configuration, so such a test case runs alone (harness design section 6).
 */
export const changesTrust = (definition: TestCaseDefinition) => definition.steps.some((step) => step.run?.kind === 'trust-list');

/** One run of a test case in one flow. */
interface Job {
  definition: TestCaseDefinition;
  flow: Flow;
}

const jobKey = (testCase: string, flow: Flow) => `${testCase} ${flow}`;

/**
 * Executes the jobs, at most `concurrency` at a time, and returns their records in the order of `jobs`. A job waits for
 * the runs of its positive controls in the same flow, which come before it. With `concurrency` above 1 the jobs that
 * change trust run after all others, one at a time; with 1 every job runs in order.
 */
async function schedule(jobs: Job[], concurrency: number, execute: (job: Job) => Promise<TestCaseRecord>): Promise<TestCaseRecord[]> {
  const records: TestCaseRecord[] = new Array(jobs.length);
  const pending = new Map<string, Promise<unknown>>();
  const run = async (index: number) => {
    const { definition, flow } = jobs[index];
    await Promise.all(controlsOf(definition).map((id) => pending.get(jobKey(id, flow))));
    records[index] = await execute(jobs[index]);
  };
  const indices = jobs.map((_, index) => index);
  const exclusive = concurrency > 1 ? indices.filter((i) => changesTrust(jobs[i].definition)) : [];
  const shared = indices.filter((i) => !exclusive.includes(i));
  // Workers take the shared jobs in order; a job's controls were taken before it, so waiting for them cannot deadlock.
  let next = 0;
  let failure: { error: unknown } | undefined;
  const worker = async () => {
    while (next < shared.length && !failure) {
      const index = shared[next++];
      const job = jobs[index];
      const done = run(index);
      pending.set(jobKey(job.definition.id, job.flow), done.catch(() => {}));
      try {
        await done;
      } catch (error) {
        failure ??= { error };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(Math.max(1, concurrency), shared.length) }, worker));
  if (failure) throw failure.error;
  for (const index of exclusive) await run(index);
  return records;
}

const matches = (id: string, pattern: string) =>
  new RegExp(`^${pattern.split('*').map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`).test(id);

/**
 * Selects the executable test cases and adds the positive controls they depend on, controls first (harness design
 * section 4.1). Text-only definitions are left out.
 */
export function selectTestCases(all: TestCaseDefinition[], only?: string[], testBook: TestBookItem[] = []): TestCaseDefinition[] {
  const definitions = all.filter(isExecutable);
  const selected = only?.length ? definitions.filter((d) => only.some((p) => matches(d.id, p))) : [...definitions];
  if (only?.length && selected.length === 0 && selectTestBook(testBook, only).length === 0) {
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

/** Selects the test book items `only` names; all of them without `only`. */
export function selectTestBook(items: TestBookItem[], only?: string[]): TestBookItem[] {
  return only?.length ? items.filter((item) => only.some((p) => matches(item.id, p))) : [...items];
}

export { durationMs };

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
    const selected = selectTestCases(options.definitions, options.only, options.testBook);
    report.testBook = selectTestBook(options.testBook ?? [], options.only).map((item) => ({ ...item, verdict: 'REVIEW' }));
    for (const item of report.testBook) log(`${item.verdict.padEnd(14)} ${item.id} (test book) ${item.method}`);
    // Only test book items selected: nothing to execute against the Relying Party.
    if (selected.length === 0) return await writeReport(report, runDir);
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
    report.run.rp = await options.adapter.describe?.().catch(() => undefined);
    log(`adapter ${options.adapter.name} set up${report.run.rp ? ` (${Object.entries(report.run.rp).map(([k, v]) => `${k} ${v}`).join(', ')})` : ''}`);
    const wallet = await ConformanceWallet.create({
      accessCertificateAnchors: [harness.pki.entities['AC-A'].anchors.issuance.certificate],
      allowInsecureUrls: true,
    });
    // Every test case once per flow, except the SessionEncryption variants, whose profile names their flow.
    const jobs = selected.flatMap((definition) => flowsOf(definition).filter((f) => requestedFlows.includes(f)).map((flow) => ({ definition, flow })));
    const concurrency = options.concurrency ?? 1;
    if (!Number.isInteger(concurrency) || concurrency < 1) throw new Error(`concurrency must be a positive integer, not ${concurrency}`);
    if (concurrency > 1) {
      const exclusive = jobs.filter((job) => changesTrust(job.definition)).length;
      log(`${jobs.length} test case runs, up to ${concurrency} at a time${exclusive ? `; the ${exclusive} that change trust lists run after them, one at a time` : ''}`);
    }
    const finished = new Map<string, TestCaseRecord>();
    const ctx: Context = { ...options, harness, wallet, runDir, report, dcApiShim, finished };
    report.results = await schedule(jobs, concurrency, async ({ definition, flow }) => {
      const started = Date.now();
      const record = await runTestCase(definition, flow, flows.includes(flow), ctx);
      record.durationMs = Date.now() - started;
      const finding = record.verdict === 'FAIL' ? knownFindingOf(options.knownFindings ?? [], record.testCase, flow) : undefined;
      if (finding) record.knownFinding = describeFinding(finding);
      finished.set(jobKey(record.testCase, flow), record);
      // With concurrency the lines come in the order the runs finish; the report keeps definition order.
      log(`${record.verdict.padEnd(14)} ${record.testCase} [${record.flow}]${record.knownFinding ? ' (known finding)' : ''}${record.reason ? ` ${record.reason}` : ''}`);
      for (const step of record.steps.filter((s) => s.verdict !== 'PASS')) log(`    step ${step.step} ${step.verdict}: ${step.reason}`);
      return record;
    });
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
  await writeJUnit(report, join(runDir, 'junit.xml'));
  return { report, reportPath };
}

interface Context extends RunOptions {
  harness: Harness;
  wallet: ConformanceWallet;
  dcApiShim: () => Promise<DcApiShim>;
  runDir: string;
  report: RunReport;
  /** The records of the finished test case runs, by `jobKey`: the verdicts of the positive controls. */
  finished: Map<string, TestCaseRecord>;
}

/** State shared by the steps of one test case. */
interface TestCaseState {
  /** The encryption key each step's request carried, by step number. */
  encryptionKeys: Map<number, NonNullable<PresentationEvidence['encryptionKey']>>;
  /** The `vp_token` entry the Conformance Wallet presented in each step, for `presentation.replay`. */
  presentations: Map<number, string>;
  /** Lists the test case changed, restored afterwards. */
  changedLists: Set<PublishableList>;
  /** The current entities of each changed list. */
  entities: Map<PublishableList, string[]>;
  /** A list retrieval still awaited, checked again after the next step. */
  pendingRetrieval?: { record: StepRecord; list: PublishableList; version: number; publishedAt: Date; checks: number };
  /** Whether the Relying Party answered a request of this test case (a started presentation). */
  rpReached: boolean;
  /** The status list URI each step's credential referenced, by step number (`StatusListSpec.uriOfStep`). */
  statusUris?: Map<number, string>;
  /** The transaction of each presentation step, by step number, for the flow steps that continue it. */
  traces?: Map<number, TransactionTrace>;
}

async function runTestCase(definition: TestCaseDefinition, flow: Flow, flowSupported: boolean, ctx: Context): Promise<TestCaseRecord> {
  const base = { testCase: definition.id, flow };
  // One passed control is enough when the definition names alternatives (for example 001a or 001b).
  const outcomes = controlsOf(definition).map((id) => ({
    id,
    verdict: ctx.finished.get(jobKey(id, flow))?.verdict ?? ('INCONCLUSIVE' as Verdict),
  }));
  const control = outcomes.find((o) => o.verdict === 'PASS') ?? outcomes[0] ?? null;
  const end = (verdict: Verdict, reason: string): TestCaseRecord => ({ ...base, verdict, reason, control, steps: [] });
  if (!flowSupported) return end('NOT APPLICABLE', `the ICS does not declare the ${flow} flow`);
  const unmet = applicability(definition, ctx.ics);
  if (unmet.length) return end('NOT APPLICABLE', `profile not met: ${unmet.join('; ')}`);
  if (control && control.verdict !== 'PASS') {
    return end('INCONCLUSIVE', `positive control ${outcomes.map((o) => o.id).join(' or ')} did not pass`);
  }
  const state: TestCaseState = { encryptionKeys: new Map(), presentations: new Map(), changedLists: new Set(), entities: new Map(), rpReached: false };
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
      case 'request':
        await runRequest(step, step.run, flow, record, save, ctx, state);
        break;
      case 'flow':
        await runFlow(step, step.run, flow, record, save, flowContext(ctx), (state.traces ??= new Map()));
        break;
      case 'error-response': {
        const action = step.run;
        await runErrorResponse(step, action, flow, record, save, flowContext(ctx), async () => {
          const started = await startPresentation(action, flow, record, save, ctx);
          state.rpReached = true;
          return started;
        });
        break;
      }
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

const flowContext = (ctx: Context) => ({
  adapter: ctx.adapter,
  wallet: ctx.wallet,
  namespace: ctx.harness.namespace,
  resultTimeoutMs: ctx.resultTimeoutMs,
  dcApiShim: ctx.dcApiShim,
});

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
  const kbMaxAgeSeconds = Number(ctx.ics.items['RP.P.6'] ?? 300);
  // Every credential gets a unique status URL (harness design section 4.6), unless the step shares the list of an
  // earlier step or names an endpoint the Test Status Provider does not serve (RP_PP_IA_Supportive).
  const allocate = () => ctx.harness.status.allocate(ctx.harness.env.runId);
  state.statusUris ??= new Map();
  let preset = await presetStatusUri(action.statusList, state.statusUris, allocate);
  // A combined presentation (UC_Presentation) forges every credential of the step; the first is the step's own, to
  // which its fault applies, and the first status list URI allocated is its own.
  const credentials = await forgePresentations(action, {
    pki: ctx.harness.pki,
    holderPublicJwk: ctx.wallet.holderKey.publicJwk,
    holderSecp256k1PublicJwk: ctx.wallet.secp256k1Key.publicJwk,
    allocateStatusUri: () => {
      const uri = preset ?? allocate();
      preset = undefined;
      return uri;
    },
    skewSeconds,
  });
  const forged = credentials[0].forged;
  const mdoc = forged.format === 'mso_mdoc';
  if (forged.statusList) state.statusUris.set(record.step, forged.statusList.uri);
  for (const [i, { forged: credential }] of credentials.entries()) {
    const prefix = i === 0 ? '' : `alongside-${i}.`;
    const isMdoc = credential.format === 'mso_mdoc';
    if (credential.statusList) {
      const { served, validToken } = credential.statusList;
      // The step's own status list may be served with another behaviour, or not at all (RP_PP_IA_Supportive).
      const endpoint = i === 0 ? action.statusList?.endpoint : undefined;
      const answer = servedAs(endpoint, credential.statusList.uri, served, ctx.ics);
      if (isServed(endpoint)) ctx.harness.status.register(credential.statusList.uri, answer.body, answer.behaviour);
      const extension = isMdoc ? 'cwt' : 'jwt';
      await save(/json|cbor/.test(served.contentType) ? `${prefix}status-list.${isMdoc ? 'cbor' : 'json'}` : `${prefix}status-list.${extension}`, served.body);
      if (!sameBody(served.body, validToken)) await save(`${prefix}status-list.valid.${extension}`, validToken);
    }
    if (credential.identifierList) {
      const { served, validToken } = credential.identifierList;
      ctx.harness.status.register(credential.identifierList.uri, served.body, { contentType: served.contentType });
      await save(`${prefix}identifier-list.cwt`, served.body);
      if (!sameBody(served.body, validToken)) await save(`${prefix}identifier-list.valid.cwt`, validToken);
    }
    await save(isMdoc ? `${prefix}credential.issuer-signed.cbor` : `${prefix}credential.sd-jwt`, credential.credential);
  }

  const query = ctx.harness.env.queries[action.query];
  const stepStart = new Date();
  // The step's list is served before the wait, so a Relying Party that refreshes it in the background sees the change.
  if (action.delaySeconds) await new Promise((resolve) => setTimeout(resolve, (action.delaySeconds ?? 0) * 1000));
  // A late response (ProtocolFlow_011) is sent once the transaction lifetime T_tx (ICS RP.P.7) has passed, plus 2 s.
  const lifetimeMs = durationMs(String(ctx.ics.items['RP.P.7'] ?? ''));
  if (action.wallet?.late && lifetimeMs === undefined) throw new Error('the ICS declares no transaction lifetime T_tx (RP.P.7)');
  const sendAt = action.wallet?.late ? Date.now() + (lifetimeMs ?? 0) + 2000 : undefined;
  const { transactionId, uri } = await startPresentation(action, flow, record, save, ctx);
  state.rpReached = true;
  const otherKey = action.response.keyOfStep ? state.encryptionKeys.get(action.response.keyOfStep) : undefined;
  if (action.response.keyOfStep && !otherKey) throw new Error(`step ${action.response.keyOfStep} recorded no encryption key`);
  const [held, ...alongside]: HeldCredential[] = credentials.map(heldCredentialOf);
  const replayed = action.response.presentationOfStep ? state.presentations.get(action.response.presentationOfStep) : undefined;
  if (action.response.presentationOfStep && !replayed) throw new Error(`step ${action.response.presentationOfStep} recorded no presentation`);
  const responseOptions = {
    enc: action.response.enc,
    fault: action.response.faults[0],
    otherTransactionKey: otherKey,
    replayedPresentation: replayed,
    skewSeconds,
    kbMaxAgeSeconds,
    maxResponseBytes: Number(ctx.ics.items['RP.P.11'] ?? 0) || undefined,
    ...(alongside.length ? { alongside } : {}),
    ...(action.wallet?.redirect === 'none' ? { followRedirect: false } : {}),
    ...(sendAt ? { sendAt } : {}),
  };

  let evidence: PresentationEvidence;
  /** Whether the Authorization Response reached the Relying Party: posted to `response_uri`, or returned to its page. */
  let delivered: boolean;
  /** Via the DC API: the network error of the page's request that forwarded the response, if it failed without an answer. */
  let forwardError: string | undefined;
  if (flow === 'dc-api') {
    let walletEvidence: PresentationEvidence | undefined;
    let answer: DcApiAnswer | undefined;
    const run = await (await ctx.dcApiShim()).run(uri, async (call): Promise<DcApiOutcome> => {
      ({ evidence: walletEvidence, answer } = await ctx.wallet.presentDcApi(call, held, responseOptions));
      // A wallet that cannot use the request answers with an OpenID4VP error (Appendix A.4), not a presentation.
      if (!answer) return { kind: 'respond', protocol: call.requests[0]?.protocol ?? '', data: { error: 'invalid_request', error_description: walletEvidence.error } };
      return { kind: 'respond', ...answer, marker: deliveryMarker(answer.data, walletEvidence.presentation) };
    }, sendAt ? { callTimeoutMs: sendAt - Date.now() + 15_000 } : {});
    evidence = walletEvidence ?? { invocationUri: uri, findings: [], error: run.error ?? 'the page made no digital credential request' };
    await recordDcApiRun(run, walletEvidence, record, save);
    await save('response.data.json', evidence.responseData && JSON.stringify(evidence.responseData, null, 2));
    delivered = Boolean(answer) && run.calls.length > 0;
    if (run.delivery) {
      record.rpResponse = { endpoint: 'dc-api-forward', url: run.delivery.url, status: run.delivery.status, body: run.delivery.body };
      forwardError = run.delivery.status === undefined ? run.delivery.error : undefined;
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
  if (evidence.presentation) state.presentations.set(record.step, evidence.presentation);
  await save(mdoc ? 'presentation.device-response.cbor' : 'presentation.sd-jwt', mdoc && evidence.presentation ? base64url.decode(evidence.presentation) : evidence.presentation);
  await save('wallet-evidence.json', JSON.stringify(evidence, null, 2));
  record.wallet = walletRecord(evidence);

  record.rpResult = await ctx.adapter.readResult(transactionId, ctx.resultTimeoutMs ?? 15_000);
  await save('rp-result.json', JSON.stringify(record.rpResult.raw, null, 2));
  // The status list or identifier list the credential references; `FETCHED` and `NOFETCH` read its log.
  const listUri = forged.statusList?.uri ?? forged.identifierList?.uri;
  const statusEntries = listUri ? ctx.harness.status.requestsFor(listUri, stepStart) : [];
  const withRequest = step.expect.codes.includes('STATUS_REQUEST');
  record.statusLog = statusEntries.map(({ url, at, status, method, target, headers }) => ({
    url,
    at,
    status,
    ...(withRequest ? { method, target, headers } : {}),
  }));

  // `ACC` compares the released attributes with the credential queries the presented credentials answer, and their
  // issued values; in a combined presentation that may be a part of the query (credential_sets, optional queries).
  const answered = credentials.map(({ forged: credential, answers }) => credentialQueryOf(query, { format: credential.format, query: answers }).id);
  const presentedQuery = { ...query, credentials: query.credentials.filter((c) => answered.includes(c.id)) };
  const issuedClaims = Object.assign({}, ...credentials.map(({ forged: credential }) => credential.claims)) as Record<string, unknown>;
  const alwaysDisclosed = credentials.flatMap(({ forged: credential }) => plainClaimsOf(credential));
  const trace: TransactionTrace = {
    transactionId,
    query: action.query,
    invocationUri: uri,
    responseUri: evidence.response?.url,
    responseForm: evidence.responseForm,
    response: evidence.response,
    redirectUri: redirectUriOf(evidence.response?.body),
    result: record.rpResult,
  };
  const traces = (state.traces ??= new Map());
  const flowEvaluation = evaluateFlowCodes(step.expect, { response: evidence.response, trace, earlier: [...traces.values()] });
  traces.set(record.step, trace);
  const presentationEvaluation = evaluate(withoutFlowCodes(step.expect), {
    result: record.rpResult,
    query: presentedQuery,
    issuedClaims,
    alwaysDisclosed,
    delivered,
    responseStatus: record.rpResponse?.status,
    responseEndpoint: record.rpResponse?.endpoint,
    responseBody: record.rpResponse?.body,
    forwardError,
    ics: ctx.ics,
    category: categoryOfQuery(action.query),
    statusRequests: record.statusLog.length,
    statusEntries,
    transactionId,
    statusFormat: action.statusList?.format,
  });
  const evaluation = flowEvaluation ? combine(withoutFlowCodes(step.expect).codes.length ? presentationEvaluation : undefined, flowEvaluation) : presentationEvaluation;
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
 * Starts `count` presentations and captures their requests at the Conformance Wallet without answering them (catalogue
 * scenario SCN-Q), then evaluates `CONF`: every request check the expectation names passes over the captured requests.
 * A check skipped because it does not apply (no `state`) passes; one skipped because a check it requires failed fails.
 */
async function runRequest(step: StepDefinition, action: RequestAction, flow: Flow, record: StepRecord, save: Save, ctx: Context, state: TestCaseState) {
  const captured: CapturedRequest[] = [];
  const count = action.count ?? 1;
  for (let i = 0; i < count; i++) {
    const { uri } = await startPresentation(action, flow, record, async (name, content) => save(`${i + 1}-${name}`, content), ctx);
    state.rpReached = true;
    let evidence: PresentationEvidence | undefined;
    if (flow === 'dc-api') {
      const run = await (await ctx.dcApiShim()).run(uri, async (call): Promise<DcApiOutcome> => {
        evidence = await ctx.wallet.startDcApi(call);
        return { kind: 'withhold' };
      });
      if (!evidence) throw new Error(run.error ?? 'the page made no digital credential request');
    } else {
      evidence = await ctx.wallet.start(uri, { requestUri: action.requestUri });
    }
    if (!evidence.captured) throw new Error('the Conformance Wallet captured no request');
    captured.push(evidence.captured);
    await save(`${i + 1}-captured-request.json`, JSON.stringify(evidence.captured, null, 2));
  }
  const pki = ctx.harness.pki;
  const anchorsOf = (list: string) => Object.values(pki.entities).filter((e) => e.spec.list === list).map((e) => e.anchors.issuance.certificate);
  const validation = await validateRequests(captured, {
    accessCertificateAnchors: anchorsOf('TL-AC'),
    registrationCertificateAnchors: anchorsOf('TL-RC'),
    trustedAuthorityKeyIds: requestAnchorKeyIds(pki),
    requireTrustedAuthorities: action.query.endsWith('_trusted_authorities'),
    // The harness runs on one machine with the Relying Party; an http URL on a loopback host stands for https.
    allowLoopbackHttp: true,
  });
  record.requestChecks = validation.checks;
  await save('request-checks.json', JSON.stringify(validation, null, 2));
  const named = step.expect.checks ?? [];
  const results = named.map((check) => validation.checks.find((c) => c.check === check));
  const failed = results.filter((r) => r && (r.status === 'fail' || (r.status === 'skip' && r.detail?.startsWith('requires'))));
  if (step.expect.codes.some((c) => c !== 'CONF') || named.length === 0) {
    record.verdict = 'INCONCLUSIVE';
    record.reason = 'a request step evaluates CONF with named request checks only';
  } else if (failed.length) {
    record.verdict = 'FAIL';
    record.reason = failed.map((r) => `${r?.check}: ${r?.status === 'skip' ? `not evaluated, ${r.detail}` : r?.detail}`).join('; ');
  } else {
    record.verdict = 'PASS';
    record.reason = `${count} request(s) pass ${named.join(', ')}`;
  }
}

/**
 * Publishes a new version of a list, asks the adapter to refresh, and waits until the Relying Party retrieved it
 * (`LIST_RETRIEVED`). A Relying Party that fetches lists only when it needs them retrieves the new version during the
 * next step, so a retrieval missing at the end of the wait is checked again after that step.
 */
async function runTrustList(action: TrustListAction, record: StepRecord, ctx: Context, state: TestCaseState) {
  // A retrieval still awaited from an earlier trust-list step is decided now, before this step publishes another version.
  await checkPendingRetrieval(state, ctx, true);
  const current = state.entities.get(action.list) ?? (action.list === 'TL-QEAA' ? trustedListEntitiesOf(ctx.harness.pki) : defaultEntitiesOf(ctx.harness.pki, action.list));
  const entities = [...current.filter((e) => !action.remove?.includes(e)), ...(action.add ?? []).filter((e) => !current.includes(e))];
  // A version the Relying Party must not use leaves the entities of the version in use unchanged.
  if (!action.faults?.length) state.entities.set(action.list, entities);
  state.changedLists.add(action.list);
  const { version, publishedAt } = await ctx.harness.publishList(action.list, entities, action);
  record.reason = `published version ${version} of ${action.list} with ${entities.join(', ')}${action.faults?.length ? `, with the fault ${action.faults.join(', ')}` : ''}`;
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
    .retrievalsOf(ctx.harness.namespace, ctx.harness.pathOf(pending.list), pending.publishedAt)
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

/**
 * The plain top-level claims of an SD-JWT VC's issuer-signed JWT: disclosed with every presentation, since they are not
 * selectively disclosable. An mdoc has none (the wallet presents only the elements it selects).
 */
function plainClaimsOf(credential: { format: string; credential: string | Uint8Array }): string[] {
  if (credential.format !== 'dc+sd-jwt' || typeof credential.credential !== 'string') return [];
  try {
    const payload = credential.credential.split('~')[0]?.split('.')[1];
    if (!payload) return [];
    return Object.keys(JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<string, unknown>).filter((claim) => claim !== '_sd' && claim !== '_sd_alg');
  } catch {
    return [];
  }
}
