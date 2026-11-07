import { randomBytes, randomInt } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import {
  type Flow,
  flowIcsItems,
  type Ics,
  type PresentationAction,
  type RelyingPartyAdapter,
  type RelyingPartyResult,
  type StepDefinition,
  type TestCaseDefinition,
  type Verdict,
  controlsOf,
} from '@rp-conformance/core';
import { buildStatusListTokenJwt, issuePidSdJwtVc } from '@rp-conformance/forge';
import { ConformanceWallet, type PresentationEvidence } from '@rp-conformance/wallet';
import { evaluate } from './evaluate';
import { type Harness, startHarness } from './harness';
import { applicability, icsAnswer } from './ics';
import { harnessInfo } from './info';

/** The flows the harness implements; the DC API shim is Phase 3. */
export const IMPLEMENTED_FLOWS: Flow[] = ['redirect'];

export interface StepRecord {
  step: number;
  text: string;
  /** Expected-result codes, for example `ACC` or `REJ + NOFETCH`. */
  expected: string;
  expectedResult: string;
  /** Named faults of the step, `null` for valid material. */
  fault: string | null;
  transactionId?: string;
  rpResponse?: { endpoint: 'response_uri'; url: string; status?: number; body?: string };
  rpResult?: RelyingPartyResult;
  wallet?: { findings: PresentationEvidence['findings']; error?: string; redirect?: PresentationEvidence['redirect']; requestFetch?: { url: string; status?: number } };
  statusLog: { url: string; at: string; status: number }[];
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
    environment: { namespace: string; statusProvider: string; trustInfrastructure: string; trustLists: { id: string; url: string }[] };
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
  log?: (line: string) => void;
}

const matches = (id: string, pattern: string) =>
  new RegExp(`^${pattern.split('*').map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`).test(id);

/** Selects the test cases and adds the positive controls they depend on, controls first (harness design section 4.1). */
export function selectTestCases(definitions: TestCaseDefinition[], only?: string[]): TestCaseDefinition[] {
  const selected = only?.length ? definitions.filter((d) => only.some((p) => matches(d.id, p))) : [...definitions];
  if (only?.length && selected.length === 0) throw new Error(`no test case matches ${only.join(', ')}`);
  for (const definition of [...selected]) {
    const ids = controlsOf(definition);
    const controls = definitions.filter((d) => ids.includes(d.id));
    if (ids.length && controls.length === 0) throw new Error(`${definition.id}: control ${ids.join(' or ')} has no definition`);
    for (const control of controls) if (!selected.includes(control)) selected.push(control);
  }
  return [...selected.filter((d) => !d.control), ...selected.filter((d) => d.control)];
}

export async function runConformance(options: RunOptions): Promise<{ report: RunReport; reportPath: string }> {
  const log = options.log ?? (() => {});
  const runId = `r${new Date().toISOString().replace(/[-:]/g, '').slice(0, 15)}-${randomBytes(3).toString('hex')}`;
  const runDir = join(options.reportDir, runId);
  const namespace = runId;
  const requestedFlows = options.flows ?? IMPLEMENTED_FLOWS;
  const notImplemented = requestedFlows.filter((f) => !IMPLEMENTED_FLOWS.includes(f));
  if (notImplemented.length) throw new Error(`flow ${notImplemented.join(', ')} is not implemented (the DC API shim is Phase 3)`);
  const flows = requestedFlows.filter((flow) => icsAnswer(options.ics, flowIcsItems[flow]) === 'Yes');

  const harness = await startHarness({ runId, harnessHost: options.harnessHost, namespace, ics: options.ics });
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
        for (const flow of flows) {
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
      for (const flow of flows.length ? flows : requestedFlows) {
        const record = await runTestCase(definition, flow, flows.includes(flow), { ...options, harness, wallet, runDir, report });
        report.results.push(record);
        log(`${record.verdict.padEnd(14)} ${record.testCase} [${record.flow}]${record.reason ? ` ${record.reason}` : ''}`);
      }
    }
  } finally {
    await options.adapter.tearDown?.().catch(() => {});
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
  return { report, reportPath };
}

interface Context extends RunOptions {
  harness: Harness;
  wallet: ConformanceWallet;
  runDir: string;
  report: RunReport;
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
  const steps: StepRecord[] = [];
  for (const [index, step] of definition.steps.entries()) {
    steps.push(await runStep(definition, flow, index + 1, step, ctx));
  }
  const order: Verdict[] = ['FAIL', 'INCONCLUSIVE', 'REVIEW', 'PASS'];
  const verdict = steps.map((s) => s.verdict).sort((a, b) => order.indexOf(a) - order.indexOf(b))[0] ?? 'INCONCLUSIVE';
  return { ...base, verdict, control, steps };
}

async function runStep(definition: TestCaseDefinition, flow: Flow, index: number, step: StepDefinition, ctx: Context): Promise<StepRecord> {
  const action: PresentationAction = step.run;
  const dir = join(ctx.runDir, 'artifacts', definition.id, flow, `step-${index}`);
  await mkdir(dir, { recursive: true });
  const artifacts: string[] = [];
  const save = async (name: string, content: string | undefined) => {
    if (content === undefined) return;
    await writeFile(join(dir, name), content);
    artifacts.push(relative(ctx.runDir, join(dir, name)));
  };
  const faults = [...action.credential.faults, ...action.statusList.faults];
  const record: StepRecord = {
    step: index,
    text: step.text,
    expected: step.expect.codes.join(' + '),
    expectedResult: step.expect.text,
    fault: faults.length ? faults.join(', ') : null,
    transactionId: undefined,
    rpResponse: undefined,
    rpResult: undefined,
    statusLog: [],
    wallet: undefined,
    artifacts,
    verdict: 'INCONCLUSIVE',
    reason: '',
  };
  if (faults.length) {
    record.reason = `faults ${faults.join(', ')} are not implemented in Phase 0`;
    return record;
  }

  // Issue the credential with a unique status URL (harness design section 4.6).
  const issuer = ctx.harness.pki.entities[action.credential.issuer];
  const statusSigner = ctx.harness.pki.entities[action.statusList.signer ?? action.credential.issuer];
  const statusUri = ctx.harness.status.allocate(ctx.harness.env.runId);
  const idx = randomInt(0, 1024);
  const statuses = new Array(1024).fill(0);
  statuses[idx] = action.statusList.status;
  const statusListToken = await buildStatusListTokenJwt({ signer: statusSigner.signers.revocation, issuer: statusSigner.issuerUri, uri: statusUri, statuses });
  ctx.harness.status.register(statusUri, statusListToken);
  const credential = await issuePidSdJwtVc({
    signer: issuer.signers.issuance,
    issuer: issuer.issuerUri,
    holderPublicJwk: ctx.wallet.holderKey.publicJwk,
    status: { uri: statusUri, idx },
  });
  await save('credential.sd-jwt', credential.compact);
  await save('status-list.jwt', statusListToken);

  const query = ctx.harness.env.queries[action.query];
  const stepStart = new Date();
  let transactionId: string;
  let invocationUri: string;
  try {
    const started = await ctx.adapter.startPresentation({ query: action.query, flow, namespace: ctx.harness.namespace });
    transactionId = started.transactionId;
    if (!('uri' in started.invocation)) throw new Error('the adapter returned no invocation URI for the redirect flow');
    invocationUri = started.invocation.uri;
  } catch (error) {
    record.reason = `could not start the presentation: ${(error as Error).message}`;
    return record;
  }
  record.transactionId = transactionId;
  await save('invocation.txt', invocationUri);

  const evidence = await ctx.wallet.present(invocationUri, credential.compact);
  await save('request.jwt', evidence.requestFetch?.body);
  await save('presentation.sd-jwt', evidence.presentation);
  await save('response.jwe', evidence.responseJwe);
  await save('wallet-evidence.json', JSON.stringify(evidence, null, 2));
  record.wallet = {
    findings: evidence.findings,
    error: evidence.error,
    redirect: evidence.redirect,
    requestFetch: evidence.requestFetch && { url: evidence.requestFetch.url, status: evidence.requestFetch.status },
  };
  if (evidence.response) {
    record.rpResponse = { endpoint: 'response_uri', url: evidence.response.url, status: evidence.response.status, body: evidence.response.body };
  }

  record.rpResult = await ctx.adapter.readResult(transactionId, ctx.resultTimeoutMs ?? 15_000);
  await save('rp-result.json', JSON.stringify(record.rpResult.raw, null, 2));
  record.statusLog = ctx.harness.status.requestsFor(statusUri, stepStart).map(({ url, at, status }) => ({ url, at, status }));

  const evaluation = evaluate(step.expect.codes, {
    result: record.rpResult,
    query,
    issuedClaims: credential.claims,
    responseStatus: evidence.response?.status,
  });
  record.verdict = evaluation.verdict;
  record.reason = evidence.error && evaluation.verdict !== 'PASS' ? `${evaluation.reason}; Conformance Wallet: ${evidence.error}` : evaluation.reason;
  return record;
}
