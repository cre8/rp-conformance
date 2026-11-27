// The runner of the issuer suite (issuer harness design sections 4 and 6): a PID Provider or Attestation Provider as
// system under test. Same conventions as the RP runner: selection with the positive controls first, gating of every
// `_UF` test case on its control in the same variant, one record per test case and variant, `report.json`,
// `summary.md` and JUnit XML. Per run it starts the harness services, the Test Wallet Provider, enrols the Provider
// through the Test Registrar and the adapter, and sets the adapter up once; then it executes the steps.
import { randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import {
  ATTESTATION_TEST_SUBJECTS,
  CATEGORY_ENTITIES,
  CATEGORY_PROFILES,
  categoryOf,
  type CheckResult,
  controlsOf,
  PROVIDER_CATEGORIES,
  type ProviderCategory,
  durationMs,
  grantFaultInfo,
  PID_TEST_SUBJECTS,
  type IssuanceAction,
  type IssuerAdapter,
  type IssuerIcs,
  type IssuerStepDefinition,
  type IssuerTestCaseDefinition,
  isCredentialRequestFault,
  isExecutable,
  isGrantFault,
  type TokenReuseAction,
  type Verdict,
  variantOf,
} from '@eudi-pcaf/core';
import { type HttpExchange, IssuanceClient, type IssuanceEvidence, type IssueOptions, credentialIdentifierOf, oauthErrorOf, walletUnitOf } from '@eudi-pcaf/issuer-wallet';
import { checkAuthorizationResponse, comparePidFormats, type IssuedOutputOptions, validateIssuedMdoc, validateIssuedSdJwtVc } from '@eudi-pcaf/validator';
import { worst } from '../evaluate';
import {
  type AttestationState,
  applyWalletEvent,
  isIssuerRequestFault,
  maintenancePeriodCheck,
  newAttestationState,
  prepareIssuance,
  rememberIssuance,
  sentAttestations,
} from './attestations';
import { isOfferCapture, issueWithFault, runMetadata, runOfferCapture } from './artifacts';
import { harnessInfo } from '../info';
import { evaluateIssuance, type IssuanceObservation } from './evaluate';
import { type IssuerHarness, startIssuerHarness } from './harness';
import { categoryIcs, issuerApplicability, issuerIcsValue, resolveConfigurations, usesTxCode } from './ics';
import { describeIssuerFinding, type IssuerKnownFinding, issuerKnownFindingOf } from './known-findings';
import { writeIssuerJUnit, writeIssuerSummary } from './report';
// Lifecycle steps (issue 22): issuer-event, observe-status, present.
import {
  evaluateObservation,
  evaluatePresentation,
  type LifecycleState,
  newLifecycleState,
  observeStatus,
  type PresentationObservation,
  present,
  runIssuerEvent,
  type StatusObservation,
  waits,
} from './status';
import { handlesSessionStep, noteSessionStep, runSessionStep, sessionApplicability } from './session';
// Issue 26: trust-list and inspect steps, batch issuance, change of subject data.
import { batchBinding, bindBatchKeys } from './batch';
import { type InspectState, runInspection } from './inspect';
import { chainingPolicy, policyExpectation, restoreTrustList, runTrustListStep, type TrustListState } from './trust';

/** The validator's clock tolerance on the issuer side: the catalogue's cap of `T_skew` (section 3.5). */
export const ISSUER_SKEW_SECONDS = 300;
/** Upper bound of a decompressed status list the reference validator reads. */
const MAX_STATUS_LIST_BYTES = 10 << 20;

/** A credential the Provider issued (`OBS-CRED`), with what it is bound to and the reference validator's result. */
export interface IssuedCredentialRecord {
  configuration: string;
  format: string;
  /** As received. */
  credential: string;
  /** The proof key the Conformance Wallet sent, public part. */
  proofKey: JsonWebKey;
  /** The KA the proof carried. */
  keyAttestation: string;
  valid: boolean;
  /** The trusted entity the issuer matched, for example `PP-T`. */
  issuer?: string;
  /** Issuer-signed claims with the disclosed values; for an mdoc the elements by namespace. */
  claims?: Record<string, unknown>;
  /** For an mdoc: the PID attributes of namespace `eu.europa.ec.eudi.pid.1`, for `pid-formats`. */
  pidClaims?: Record<string, unknown>;
  checks: CheckResult[];
}

export interface IssuerStepRecord {
  step: number;
  /** The step action, for example `issuance`. */
  action: string;
  text: string;
  /** Expected-result codes, for example `ISS` or `REJ`. */
  expected: string;
  expectedResult: string;
  /** The named fault of the step, `null` for valid material. */
  fault: string | null;
  walletUnit?: string;
  subject?: string;
  /** The offer the adapter created (`OBS-ADM`). */
  offer?: { sessionId: string; offer: string; byReference: boolean; txCode: boolean; configurations: string[] };
  /** Every request to the Provider and its answer, with headers (`OBS-HTTP`). */
  exchanges: HttpExchange[];
  /** Whether the Provider issued an access token, and its type. */
  token?: { tokenType: string };
  credentials: IssuedCredentialRecord[];
  /** Checks over all credentials of the step, for example `pid-formats` (both formats of one issuance). */
  stepChecks?: CheckResult[];
  /** The named checks over the captured metadata or offer (`CONF`). */
  checks?: CheckResult[];
  /** The reference validator's credential request checks over the faulty request (point `credential-request`). */
  requestChecks?: CheckResult[];
  /** Why the flow stopped before a credential arrived. */
  error?: string;
  /** `issuer-event`: what the adapter reported done (`OBS-ADM`). */
  event?: { sessionId: string; at: string; status: string };
  /** `observe-status`: every poll of the published lists and the publication checks (`OBS-SL`). */
  statusObservation?: StatusObservation;
  /** `present`: the reference Relying Party's result. */
  presentation?: Omit<PresentationObservation, 'result'>;
  /** Issue 26, `inspect`: the named checks over what earlier steps captured. */
  inspection?: CheckResult[];
  artifacts: string[];
  verdict: Verdict;
  reason: string;
}

export interface IssuerTestCaseRecord {
  testCase: string;
  /** The variant, for example `SD+PA` (`variantOf`). */
  variant: string;
  verdict: Verdict;
  reason?: string;
  /** For a FAIL that is a known finding of the Provider: the finding and where it is tracked. */
  knownFinding?: string;
  durationMs?: number;
  control: { id: string; verdict: Verdict } | null;
  steps: IssuerStepRecord[];
}

export interface IssuerRunReport {
  run: {
    id: string;
    /** The kind of system under test. */
    sut: 'issuer';
    startedAt: string;
    finishedAt?: string;
    adapter: string;
    /** What the adapter reports about the Provider under test, for example its version. */
    provider?: Record<string, string>;
    ics: IssuerIcs;
    harness: ReturnType<typeof harnessInfo>;
    environment: {
      namespace: string;
      statusProvider: string;
      trustInfrastructure: string;
      trustLists: { id: string; url: string }[];
      /** How the Test Registrar enrolled the Provider (issuer harness design section 5.3). */
      enrolment?: { entity: string; method: 'csr' | 'generated'; credentialSigners: number; statusListSigner: boolean };
      walletProviderStatusLists: { id: string; uri: string }[];
      /**
       * Issue 27: the Provider instance of each category the run executed (the first one is also described above), with
       * its namespace, enrolment and what the adapter reports.
       */
      categories?: { category: ProviderCategory; namespace: string; entity: string; enrolment?: IssuerRunReport['run']['environment']['enrolment']; provider?: Record<string, string>; trustLists: { id: string; url: string }[] }[];
    };
    summary: Partial<Record<Verdict, number>>;
    /** Why the run could not execute its test cases, if it could not. */
    error?: string;
  };
  results: IssuerTestCaseRecord[];
}

export interface IssuerRunOptions {
  adapter: IssuerAdapter;
  ics: IssuerIcs;
  definitions: IssuerTestCaseDefinition[];
  /** Test case IDs or patterns with `*`. */
  only?: string[];
  reportDir: string;
  /** Host name under which the Provider reaches the harness services. */
  harnessHost: string;
  knownFindings?: IssuerKnownFinding[];
  log?: (line: string) => void;
  /**
   * Issue 27: a fresh adapter for the Provider instance of another category, which runs in parallel with the first one
   * (one adapter per instance, for example one EUDIPLO tenant each). Without it the categories run one after another
   * with `adapter`.
   */
  createAdapter?: () => IssuerAdapter;
  /**
   * The longest a step may wait for an artifact to expire (a lifetime plus one hour, catalogue section 3.5), seconds;
   * default 0. A step that would wait longer is NOT APPLICABLE in the run, and the test cases with such steps run last.
   */
  maxWaitSeconds?: number;
}

const matches = (id: string, pattern: string) =>
  new RegExp(`^${pattern.split('*').map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`).test(id);

/**
 * Selects the executable issuer definitions `only` names (all without it) and adds the positive controls they depend
 * on, controls first, as on the RP side. A test case has one definition per variant; all of them are selected.
 */
export function selectIssuerTestCases(all: IssuerTestCaseDefinition[], only?: string[]): IssuerTestCaseDefinition[] {
  const definitions = all.filter(isExecutable);
  const selected = only?.length ? definitions.filter((d) => only.some((p) => matches(d.id, p))) : [...definitions];
  if (only?.length && selected.length === 0) {
    const textOnly = all.filter((d) => !isExecutable(d) && only.some((p) => matches(d.id, p)));
    throw new Error(`no executable issuer test case matches ${only.join(', ')}${textOnly.length ? ` (text only: ${textOnly.map((d) => d.id).join(', ')})` : ''}`);
  }
  for (const definition of [...selected]) {
    const ids = controlsOf(definition);
    const controls = definitions.filter((d) => ids.includes(d.id));
    if (ids.length && controls.length === 0) throw new Error(`${definition.id}: control ${ids.join(' or ')} has no definition`);
    for (const control of controls) if (!selected.includes(control)) selected.push(control);
  }
  return [...selected.filter((d) => !d.control), ...selected.filter((d) => d.control)];
}

export async function runIssuerConformance(options: IssuerRunOptions): Promise<{ report: IssuerRunReport; reportPath: string }> {
  const log = options.log ?? (() => {});
  const runId = `i${new Date().toISOString().replace(/[-:]/g, '').slice(0, 15)}-${randomBytes(3).toString('hex')}`;
  const runDir = join(options.reportDir, runId);
  const selected = selectIssuerTestCases(options.definitions, options.only);
  const report: IssuerRunReport = {
    run: {
      id: runId,
      sut: 'issuer',
      startedAt: new Date().toISOString(),
      adapter: options.adapter.name,
      ics: options.ics,
      harness: harnessInfo(),
      environment: { namespace: runId, statusProvider: '', trustInfrastructure: '', trustLists: [], walletProviderStatusLists: [] },
      summary: {},
    },
    results: [],
  };
  // Issue 27: one Provider instance per category (catalogue section 2.1: the `AP_*` test cases run with the category
  // variant `Q`, `PB` or `E`), each with its own harness services, enrolment and adapter set-up. A category the ICS
  // declares no instance for is NOT APPLICABLE; the others run in parallel when the CLI can create adapters.
  const groups = PROVIDER_CATEGORIES.map((category) => ({ category, definitions: selected.filter((d) => categoryOf(d) === category), ics: categoryIcs(options.ics, category) })).filter((g) => g.definitions.length);
  for (const group of groups.filter((g) => !g.ics)) {
    const reason = `the ICS declares no ${CATEGORY_ENTITIES[group.category].name} (ICS-01 ${CATEGORY_PROFILES[group.category]})`;
    for (const definition of group.definitions) report.results.push({ testCase: definition.id, variant: variantOf(definition), verdict: 'NOT APPLICABLE', reason, control: null, steps: [] });
  }
  const running = groups.filter((g): g is typeof g & { ics: IssuerIcs } => g.ics !== undefined);
  const runGroup = (group: (typeof running)[number], index: number, adapter: IssuerAdapter) =>
    runCategory({ ...options, adapter, ics: group.ics }, { category: group.category, definitions: group.definitions, namespace: index === 0 ? runId : `${runId}-${group.category.toLowerCase()}`, first: index === 0, runId, runDir, report, log });
  if (options.createAdapter) {
    await Promise.all(running.map((group, index) => runGroup(group, index, index === 0 ? options.adapter : (options.createAdapter as () => IssuerAdapter)())));
  } else {
    for (const [index, group] of running.entries()) await runGroup(group, index, options.adapter);
  }
  return writeIssuerReport(report, runDir);
}

/**
 * The test cases of one category against the Provider instance of that category: its harness services, the Test
 * Wallet Provider, its enrolment by the Test Registrar as the category's entity, the adapter's set-up; then the steps.
 */
async function runCategory(
  options: IssuerRunOptions,
  group: { category: ProviderCategory; definitions: IssuerTestCaseDefinition[]; namespace: string; first: boolean; runId: string; runDir: string; report: IssuerRunReport; log: (line: string) => void },
): Promise<void> {
  const { category, definitions: selected, namespace, report, runDir, log } = group;
  // Issue 20: a grant fault that waits past a lifetime (`--max-wait`) puts its test case with the waiting ones.
  const grantWaits = (d: IssuerTestCaseDefinition) => d.steps.some((step) => step.run?.kind === 'issuance' && step.run.faults.some((f) => isGrantFault(f) && grantFaultInfo(f).waitsFor));
  const harness = await startIssuerHarness({ runId: group.runId, namespace, harnessHost: options.harnessHost, ics: options.ics, category });
  const entity = CATEGORY_ENTITIES[category].entity;
  const described: NonNullable<IssuerRunReport['run']['environment']['categories']>[number] = { category, namespace, entity, trustLists: [] };
  (report.run.environment.categories ??= []).push(described);
  if (group.first) {
    Object.assign(report.run.environment, {
      namespace,
      statusProvider: harness.status.baseUrl,
      trustInfrastructure: harness.trust.baseUrl,
      walletProviderStatusLists: Object.values(harness.twp.statusLists).map(({ id, uri }) => ({ id, uri })),
    });
  }
  const label = category === 'PID' ? '' : ` [${category}]`;
  try {
    log(`issuer run ${group.runId}${label}: harness services at ${harness.status.baseUrl} (status) and ${harness.trust.baseUrl} (trust), Provider enrolled as ${entity}`);
    try {
      const env = await harness.enrol(options.adapter);
      described.trustLists = env.trustLists.map(({ id, url }) => ({ id, url }));
      const enrolment = harness.enrolment;
      if (enrolment) {
        described.enrolment = {
          entity: enrolment.entity,
          method: enrolment.method,
          credentialSigners: enrolment.credentialSigners.length,
          statusListSigner: Boolean(enrolment.statusListSigner),
        };
      }
      if (group.first) {
        report.run.environment.trustLists = described.trustLists;
        if (described.enrolment) report.run.environment.enrolment = described.enrolment;
      }
      await options.adapter.setUp(env, namespace);
    } catch (error) {
      // Without an enrolled and configured Provider no test case can produce a verdict.
      const message = `${category === 'PID' ? '' : `${CATEGORY_ENTITIES[category].name}: `}enrolment or adapter set-up failed: ${(error as Error).message}`;
      report.run.error = report.run.error ? `${report.run.error}; ${message}` : message;
      for (const definition of selected) {
        report.results.push({ testCase: definition.id, variant: variantOf(definition), verdict: 'INCONCLUSIVE', reason: message, control: null, steps: [] });
      }
      log(message);
      return;
    }
    const provider = await options.adapter.describe?.().catch(() => undefined);
    if (provider) described.provider = provider;
    if (group.first && provider) report.run.provider = provider;
    log(`adapter ${options.adapter.name}${label} set up${provider ? ` (${Object.entries(provider).map(([k, v]) => `${k} ${v}`).join(', ')})` : ''}`);
    const execute = async (definition: IssuerTestCaseDefinition) => {
      const started = Date.now();
      const record = await runIssuerTestCase(definition, { ...options, harness, runDir, report });
      record.durationMs = Date.now() - started;
      const finding = record.verdict === 'FAIL' ? issuerKnownFindingOf(options.knownFindings ?? [], record.testCase, record.variant) : undefined;
      if (finding) record.knownFinding = describeIssuerFinding(finding);
      report.results.push(record);
      log(`${record.verdict.padEnd(14)} ${record.testCase} [${record.variant}]${record.knownFinding ? ' (known finding)' : ''}${record.reason ? ` ${record.reason}` : ''}`);
      for (const step of record.steps) log(`    step ${step.step} ${step.verdict}: ${step.reason}`);
    };
    // Test cases whose steps wait (`REVOKED(t)`, polling across `exp`) run after the others and in parallel (design
    // section 6.3); a test case gated on a control still runs after it.
    const waiting = selected.filter((d) => (waits(d.steps) || grantWaits(d)) && !d.control);
    for (const definition of selected.filter((d) => !waiting.includes(d))) await execute(definition);
    // Issue 26: a test case that changes the subject's data (`changeSubject`) runs alone, after every other one.
    const exclusive = waiting.filter(changesSubject);
    await Promise.all(waiting.filter((d) => !exclusive.includes(d)).map(execute));
    for (const definition of exclusive) await execute(definition);
  } finally {
    await options.adapter.tearDown?.().catch(() => {});
    await harness.stop();
  }
}

async function writeIssuerReport(report: IssuerRunReport, runDir: string): Promise<{ report: IssuerRunReport; reportPath: string }> {
  report.run.finishedAt = new Date().toISOString();
  report.run.summary = {};
  for (const result of report.results) report.run.summary[result.verdict] = (report.run.summary[result.verdict] ?? 0) + 1;
  await mkdir(runDir, { recursive: true });
  const reportPath = join(runDir, 'report.json');
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  await writeIssuerSummary(report, join(runDir, 'summary.md'));
  await writeIssuerJUnit(report, join(runDir, 'junit.xml'));
  return { report, reportPath };
}

interface Context extends IssuerRunOptions {
  harness: IssuerHarness;
  runDir: string;
  report: IssuerRunReport;
}

/**
 * State shared by the steps of one test case: one issuance client (one DPoP key) per Wallet Unit (design section 5.1),
 * and what the lifecycle steps read of earlier steps.
 */
interface TestCaseState extends LifecycleState, InspectState, TrustListState {
  clients: Map<string, IssuanceClient>;
  /** Moved status references and replay values of the Wallet Units (issue 19). */
  attestations: AttestationState;
  /** Offers by value captured in the test case (`PP_WS_MS_Offer_002`). */
  offersByValue: Record<string, unknown>[];
  /** The evidence of each issuance step (1-based), for `token-reuse` (issue 20). */
  evidence: Map<number, IssuanceEvidence>;
}

/** The plain client of a Wallet Unit (one DPoP key per unit), as `token-reuse` sends with it. */
async function clientOf(unit: string, ctx: Context, state: TestCaseState): Promise<IssuanceClient> {
  let client = state.clients.get(unit);
  if (!client) {
    client = await IssuanceClient.create(walletUnitOf(ctx.harness.twp, unit as Parameters<typeof walletUnitOf>[1]), { allowInsecureUrls: true });
    state.clients.set(unit, client);
  }
  return client;
}

async function runIssuerTestCase(definition: IssuerTestCaseDefinition, ctx: Context): Promise<IssuerTestCaseRecord> {
  const variant = variantOf(definition);
  const base = { testCase: definition.id, variant };
  const outcomes = controlsOf(definition).map((id) => ({
    id,
    verdict: ctx.report.results.find((r) => r.testCase === id && r.variant === variant)?.verdict ?? ('INCONCLUSIVE' as Verdict),
  }));
  const control = outcomes.find((o) => o.verdict === 'PASS') ?? outcomes[0] ?? null;
  const end = (verdict: Verdict, reason: string): IssuerTestCaseRecord => ({ ...base, verdict, reason, control, steps: [] });
  const unmet = [...issuerApplicability(definition, ctx.ics), ...sessionApplicability(definition, ctx.ics)];
  if (unmet.length) return end('NOT APPLICABLE', `profile not met: ${unmet.join('; ')}`);
  if (control && control.verdict !== 'PASS') return end('INCONCLUSIVE', `positive control ${outcomes.map((o) => o.id).join(' or ')} did not pass in ${variant}`);
  // Issue 26: a test case that needs an adapter hook the adapter lacks does not apply (issuer harness design section 5.4).
  if (changesSubject(definition) && !ctx.adapter.changeSubject) return end('NOT APPLICABLE', 'the adapter offers no changeSubject (ICS-06.change_subject)');
  const state: TestCaseState = { clients: new Map(), attestations: newAttestationState(), offersByValue: [], evidence: new Map(), ...newLifecycleState(), captured: new Map(), startedAt: new Date() };
  const steps: IssuerStepRecord[] = [];
  try {
    for (const [index, step] of definition.steps.entries()) steps.push(noteSessionStep(state, await runIssuerStep(definition, variant, index + 1, step, ctx, state)));
  } finally {
    // Issue 26: the default TL-WP again after a test case that published another version.
    await restoreTrustList(state, trustContext(ctx)).catch((error) => ctx.log?.(`    could not restore TL-WP: ${(error as Error).message}`));
  }
  // A step that does not apply to the Provider (NOT APPLICABLE) does not count, unless no step applies.
  const applicable = steps.filter((s) => s.verdict !== 'NOT APPLICABLE');
  const skipped = steps.filter((s) => s.verdict === 'NOT APPLICABLE').map((s) => `step ${s.step} not applicable: ${s.reason}`);
  return { ...base, verdict: applicable.length ? worst(applicable.map((s) => s.verdict)) : 'NOT APPLICABLE', ...(skipped.length && applicable.length ? { reason: skipped.join('; ') } : {}), control, steps };
}

async function runIssuerStep(
  definition: IssuerTestCaseDefinition,
  variant: string,
  index: number,
  step: IssuerStepDefinition,
  ctx: Context,
  state: TestCaseState,
): Promise<IssuerStepRecord> {
  const faults = step.run?.kind === 'issuance' ? step.run.faults : [];
  const record: IssuerStepRecord = {
    step: index,
    action: step.run?.kind ?? 'none',
    text: step.text,
    expected: step.expect.codes.join(' + '),
    expectedResult: step.expect.text,
    fault: faults.length ? faults.join(', ') : null,
    exchanges: [],
    credentials: [],
    artifacts: [],
    verdict: 'INCONCLUSIVE',
    reason: '',
  };
  const dir = join(ctx.runDir, 'artifacts', definition.id, variant, `step-${index}`);
  const save = async (name: string, content: string) => {
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, name), content);
    record.artifacts.push(relative(ctx.runDir, join(dir, name)));
  };
  try {
    // Issue 25: DPoP, batch, re-issuance, deferred, notification and robustness steps run on the session client.
    if (handlesSessionStep(definition, step)) await runSessionStep(step, index, record, save, ctx, state);
    else if (step.run?.kind === 'metadata') await runMetadata(step.expect, record, save, ctx);
    // Issue 26: issuances of test cases that run in parallel go one at a time; only their waits overlap.
    else if (step.run?.kind === 'issuance') {
      const action = step.run;
      await oneAtATime(ctx.harness, () => runIssuance(step, action, record, save, ctx, state));
    }
    else if (step.run?.kind === 'token-reuse') await runTokenReuse(step, step.run, record, save, ctx, state);
    else if (step.run?.kind === 'wallet-event' && step.expect.codes.every((code) => code === 'INFO')) {
      record.walletUnit = step.run.walletUnit ?? 'CW-1';
      const served = await applyWalletEvent(step.run, {
        twp: ctx.harness.twp,
        statusProvider: ctx.harness.status,
        namespace: ctx.harness.namespace,
        state: state.attestations,
        skewSeconds: ISSUER_SKEW_SECONDS,
      });
      record.verdict = 'PASS';
      record.reason = `recorded: ${served}`;
      // Issue 26: a revocation by the Test Wallet Provider is the event `REVOKED(T_chain)` counts from.
      if (step.run.event !== 'status-list') state.events.set(index, { at: new Date(), status: step.run.event });
    }
    // Issue 26: trust-list and inspect steps.
    else if (step.run?.kind === 'trust-list') Object.assign(record, await runTrustListStep(step.run, state, trustContext(ctx)));
    else if (step.run?.kind === 'inspect') {
      const { checks, ...evaluation } = await runInspection(step.run, step.expect, state, { harness: ctx.harness, ics: ctx.ics, harnessHost: ctx.harnessHost });
      record.inspection = checks;
      await save('inspection.json', `${JSON.stringify(checks, null, 2)}\n`);
      Object.assign(record, evaluation);
    }
    else if (step.run?.kind === 'issuer-event' || step.run?.kind === 'observe-status' || step.run?.kind === 'present') {
      await runLifecycleStep(step, step.run, record, save, ctx, state);
    } else record.reason = step.run ? `the step action ${step.run.kind} is not implemented yet` : 'the step is text only';
  } catch (error) {
    record.verdict = 'INCONCLUSIVE';
    record.reason = `the harness could not execute the step: ${(error as Error).message}`;
  }
  return record;
}

/** What the issuance client and the issuance action support so far; anything else leaves the step INCONCLUSIVE. */
function unsupported(action: IssuanceAction, adapter: IssuerRunOptions['adapter']): string | undefined {
  if (action.grant === 'authorization_code' && !adapter.authenticateSubject) return 'the adapter cannot authenticate the subject (no authenticateSubject)';
  const notImplemented = action.faults.filter((fault) => !isCredentialRequestFault(fault) && !isIssuerRequestFault(fault) && !isGrantFault(fault));
  if (notImplemented.length) return `issuer faults are not implemented yet (${notImplemented.join(', ')})`;
  const options: string[] = (['stopAfterToken', 'deferred', 'encryption'] as const).filter((option) => action[option]);
  // Issue 26: a valid batch (batch.ts); a batch with a fault is issue 25's.
  if ((action.batchSize ?? 1) > 1 && action.faults.length) options.push('batchSize with a fault');
  return options.length ? `the issuance option(s) ${options.join(', ')} are not implemented yet` : undefined;
}

/** `SCN-I` (issuer catalogue section 3.7): offer from the adapter, the grant by the issuance client, `OBS-CRED`. */
async function runIssuance(
  step: IssuerStepDefinition,
  action: IssuanceAction,
  record: IssuerStepRecord,
  save: (name: string, content: string) => Promise<void>,
  ctx: Context,
  state: TestCaseState,
): Promise<void> {
  if (action.portraitOptOut && issuerIcsValue(ctx.ics, 'ICS-17.portrait_opt_out') !== 'Yes') {
    record.verdict = 'NOT APPLICABLE';
    record.reason = 'the ICS declares no portrait opt-out (ICS-17.portrait_opt_out)';
    return;
  }
  if (isOfferCapture(step.expect)) return runOfferCapture(step.expect, action, record, save, ctx, state);
  // Issue 27 (AP_WS_SM_KeyAttestation_101_UF): a KA level the Provider accepts (ICS-04) is not below what it requires.
  const level = action.faults.map((f) => /^ka\.(key-storage|user-authentication)-(moderate|basic)$/.exec(f)).find(Boolean);
  if (level) {
    const item = level[1] === 'key-storage' ? 'ICS-04.key_storage' : 'ICS-04.user_authentication';
    const accepted = (issuerIcsValue(ctx.ics, item) ?? 'iso_18045_high').split(',').map((v) => v.trim());
    if (accepted.includes(`iso_18045_${level[2]}`)) {
      record.verdict = 'NOT APPLICABLE';
      record.reason = `the Provider accepts iso_18045_${level[2]} (${item}: ${accepted.join(', ')}), so it is not below what the configuration requires`;
      return;
    }
  }
  const missing = unsupported(action, ctx.adapter);
  if (missing) {
    record.reason = missing;
    return;
  }
  const unit = action.walletUnit ?? 'CW-1';
  const subject = action.subject ?? 'SUBJ-1';
  // Issue 26: POLICY (ICS-15) becomes the expectation the declaration gives; issue 27: also POLICY (ICS-18).
  const policy = policyExpectation(step.expect, state, ctx.ics);
  if (policy) step = { ...step, expect: policy.expect };
  record.walletUnit = unit;
  record.subject = subject;
  const configurations = resolveConfigurations(action.configurations, ctx.ics);
  const txCode = usesTxCode(ctx.ics);
  const grantFault = action.faults.find(isGrantFault);
  if (grantFault && grantFaultInfo(grantFault).target === 'tx-code' && !txCode) {
    record.verdict = 'NOT APPLICABLE';
    record.reason = 'the Provider declares offers without tx_code only (ICS-03.tx_code)';
    return;
  }
  const byReference = action.offerByReference ?? false;
  const offer = await ctx.adapter.createOffer({ subject, configurations, grant: action.grant, byReference, txCode, ...(action.portraitOptOut ? { portraitOptOut: true } : {}) });
  record.offer = { sessionId: offer.sessionId, offer: offer.offer, byReference, txCode: offer.txCode !== undefined, configurations };

  // A plain issuance reuses the unit's client (one DPoP key per Wallet Unit); a step with a fault, a moved status
  // reference or another proof type gets a client with its own binding and hooks (issue 19).
  const batch = (action.batchSize ?? 1) > 1 ? action.batchSize! : undefined;
  const plain = !batch && !action.faults.some(isIssuerRequestFault) && !action.proofType && !action.keyAttestationNonce && !state.attestations.status.has(unit);
  const prepared = plain ? undefined : await prepareIssuance(action, ctx.harness.twp, state.attestations);
  // Issue 26: a valid batch over the keys of one KA.
  const batched = batch ? batchBinding(ctx.harness.twp, unit, batch, prepared?.unit) : undefined;
  let client = plain ? state.clients.get(unit) : undefined;
  if (!client) {
    client = await IssuanceClient.create(batched?.unit ?? prepared?.unit ?? walletUnitOf(ctx.harness.twp, unit), {
      allowInsecureUrls: true,
      ...(batched ? { hooks: batched.hooks } : prepared ? { hooks: prepared.hooks } : {}),
    });
    if (plain) state.clients.set(unit, client);
  }
  const requestFault = action.faults.find(isCredentialRequestFault);
  let evidence: IssuanceEvidence;
  if (requestFault) {
    const grant = await grantOptions(action, subject, txCode, ctx);
    // `identifier-foreign` (issue 20 makes it executable, AC only): a `credential_identifier` of another session's token.
    const foreignIdentifier = requestFault === 'credential-request.identifier-foreign' ? await foreignCredentialIdentifier(action, subject, configurations, txCode, ctx, state) : undefined;
    const faulty = await issueWithFault(requestFault, offer, configurations[0] as string, unit, ctx, {
      ...(grant.grant ? { grant: grant.grant } : {}),
      ...(grant.authenticate ? { authenticate: grant.authenticate } : {}),
      ...(foreignIdentifier !== undefined ? { foreignIdentifier } : {}),
    });
    evidence = faulty.evidence;
    if (faulty.requestChecks) record.requestChecks = faulty.requestChecks;
    if (faulty.notApplicable) {
      record.exchanges = evidence.exchanges;
      // The fault cannot be built against this Provider (nothing faulty was sent): NOT APPLICABLE, with the reason.
      record.verdict = 'NOT APPLICABLE';
      record.reason = `the fault ${requestFault} cannot be applied: ${faulty.notApplicable}`;
      return;
    }
  } else {
    evidence = await client.issue({ offer: offer.offer, ...(offer.txCode !== undefined ? { txCode: offer.txCode } : {}), credentialConfigurationIds: configurations, ...(action.credentialIdentifier ? { credentialIdentifier: true } : {}), ...(action.proof ? { proof: action.proof } : {}), ...(await grantOptions(action, subject, txCode, ctx)) });
  }
  // `REJ:invalid_nonce, then ISS`: the same request again, without the fault, with a fresh `c_nonce`.
  const firstAttempt = { exchanges: evidence.exchanges.length, credentials: evidence.credentials.length };
  if (action.retryWithFreshNonce && prepared && evidence.error && evidence.token && evidence.metadata) {
    prepared.withoutFault();
    try {
      const cNonce = await client.requestNonce(evidence.metadata.result, evidence);
      await client.requestCredential(evidence.metadata.result, evidence.token, configurations[0], cNonce, evidence);
      delete evidence.error;
    } catch (error) {
      evidence.error = `retry with a fresh c_nonce: ${(error as Error).message}`;
    }
  }
  if (batched) bindBatchKeys(evidence.credentials, batched.keys());
  state.evidence.set(record.step, evidence);
  rememberIssuance(state.attestations, unit, evidence);
  state.issued.set(record.step, { sessionId: offer.sessionId, credentials: evidence.credentials });
  record.exchanges = evidence.exchanges;
  if (evidence.waitExceeded) {
    record.verdict = 'NOT APPLICABLE';
    record.reason = `${evidence.error}; run with a larger --max-wait to execute it`;
    await save('issuance.json', `${JSON.stringify({ offer: record.offer, grant: evidence.grant, exchanges: evidence.exchanges }, null, 2)}\n`);
    return;
  }
  if (evidence.token) record.token = { tokenType: evidence.token.tokenType };
  if (evidence.error) record.error = evidence.error;
  // Issue 26: after `changeSubject` the subject's data are those of the subject it was changed to.
  const output = outputOptions(step, action, state.subjects?.get(subject) ?? subject, ctx);
  // Issue 27: a configuration the ICS declares not device-bound (`ICS-04.NDB.*`) issues credentials bound to no key.
  record.credentials = await validateCredentials(evidence, ctx, output, action.configurations.some((c) => c.startsWith('ICS-04.NDB.')));
  state.captured?.set(record.step, { evidence, checks: record.credentials.map((c) => c.checks), receivedAt: new Date() });
  if (output.checks.includes('pid-formats')) {
    const sdJwt = record.credentials.find((c) => c.format === 'dc+sd-jwt');
    const mdoc = record.credentials.find((c) => c.format === 'mso_mdoc');
    record.stepChecks = [comparePidFormats(sdJwt?.claims, mdoc?.pidClaims)];
  }
  if (step.expect.checks?.includes('maintenance-period')) {
    const sent = sentAttestations(evidence.exchanges);
    for (const credential of record.credentials) credential.checks.push(maintenancePeriodCheck(credential.credential, sent));
  }
  for (const [i, credential] of record.credentials.entries()) await save(`credential-${i + 1}.txt`, credential.credential);
  await save('issuance.json', `${JSON.stringify({ offer: record.offer, offerObject: evidence.offer, metadata: evidence.metadata, grant: evidence.grant, exchanges: evidence.exchanges }, null, 2)}\n`);

  // `proof.p521` applies only where the configuration does not advertise ES512 for `jwt` proofs (catalogue
  // PP_WS_SM_ProofOfPossession_009_UF: "P-521 if not advertised").
  const proofAlgorithms = (evidence.metadata?.result.credentialIssuer.credential_configurations_supported[configurations[0]] as
    | { proof_types_supported?: { jwt?: { proof_signing_alg_values_supported?: string[] } } }
    | undefined)?.proof_types_supported?.jwt?.proof_signing_alg_values_supported;
  if (action.faults.includes('proof.p521') && proofAlgorithms?.includes('ES512')) {
    record.verdict = 'NOT APPLICABLE';
    record.reason = `the configuration advertises ES512 for jwt proofs (${proofAlgorithms.join(', ')}); ${record.credentials.length ? `issued ${record.credentials.length} credential(s)` : 'no credential issued'}`;
    return;
  }
  const evaluation = action.retryWithFreshNonce
    ? evaluateRetry(step, evidence, record.credentials, firstAttempt)
    : evaluateIssuance(step.expect, { ...observationOf(evidence, record.credentials, record.stepChecks), ...conformanceOf(evidence) });
  record.verdict = evaluation.verdict;
  record.reason = policy ? `${policy.reason}: ${evaluation.reason}` : evaluation.reason;
}

/**
 * What the output checks the step's expectation names (`checks`) compare with: the subject's data, and the validity
 * period the ICS declares for the step's configuration (`ICS-05.validity_period`, `ICS-05.short.validity_period` for a
 * short-lived one) within the declared timestamp precision (`ICS-16.timestamp_precision`).
 */
function outputOptions(step: IssuerStepDefinition, action: IssuanceAction, subject: string, ctx: Context): IssuedOutputOptions {
  const seconds = (key: string) => {
    const ms = durationMs(issuerIcsValue(ctx.ics, key));
    return ms === undefined ? undefined : ms / 1000;
  };
  const short = action.configurations.some((c) => c.startsWith('ICS-05.short.'));
  const declared = seconds(short ? 'ICS-05.short.validity_period' : 'ICS-05.validity_period');
  const precision = seconds('ICS-16.timestamp_precision');
  return {
    checks: (step.expect.checks ?? []) as IssuedOutputOptions['checks'],
    subject: PID_TEST_SUBJECTS[subject as keyof typeof PID_TEST_SUBJECTS],
    // Issue 27: an Attestation Provider issues `default_credential_A` with the subject's attestation data.
    attestationSubject: ATTESTATION_TEST_SUBJECTS[subject as keyof typeof ATTESTATION_TEST_SUBJECTS],
    ...(declared !== undefined ? { declaredValiditySeconds: declared } : {}),
    ...(precision !== undefined ? { precisionSeconds: precision } : {}),
    fetchTypeMetadata: async (url) => {
      const response = await ctx.harness.fetch(url);
      return { status: response.status, body: new Uint8Array(await response.arrayBuffer()) };
    },
  };
}

/** The lifecycle steps (status.ts): `issuer-event`, `observe-status` and `present`, with their evidence. */
async function runLifecycleStep(
  step: IssuerStepDefinition,
  action: Extract<IssuerStepDefinition['run'], { kind: 'issuer-event' | 'observe-status' | 'present' }>,
  record: IssuerStepRecord,
  save: (name: string, content: string) => Promise<void>,
  ctx: Context,
  state: TestCaseState,
): Promise<void> {
  const lifecycle = { harness: ctx.harness, ics: ctx.ics, harnessHost: ctx.harnessHost, ...(ctx.log ? { log: ctx.log } : {}) };
  if (action.kind === 'issuer-event') {
    const { event, ...evaluation } = await runIssuerEvent(action, record.step, state, { ...lifecycle, adapter: ctx.adapter });
    if (event) record.event = event;
    Object.assign(record, evaluation);
    return;
  }
  if (action.kind === 'observe-status') {
    const observation = await observeStatus(action, record.step, state, lifecycle);
    record.statusObservation = observation;
    await save('status-observation.json', `${JSON.stringify(observation, null, 2)}\n`);
    // Issue 27: POLICY (ICS-07) becomes REVOKED(T_chain) when the Provider declares it chains, UNCHANGED otherwise.
    const policy = chainingPolicy(step.expect, ctx.ics);
    const evaluation = evaluateObservation(policy?.expect ?? step.expect, observation, ctx.ics);
    Object.assign(record, policy ? { ...evaluation, reason: `${policy.reason}: ${evaluation.reason}` } : evaluation);
    return;
  }
  const { result, ...presentation } = await present(action, state, lifecycle);
  record.presentation = presentation;
  await save('presentation.json', `${JSON.stringify({ ...presentation, result }, null, 2)}\n`);
  Object.assign(record, evaluatePresentation(step.expect, { ...presentation, ...(result ? { result } : {}) }));
}

/**
 * A step with `retryWithFreshNonce`: its first code (`REJ:invalid_nonce`) is judged on the faulty attempt, the others
 * (`ISS`) on the retry; the step's verdict is the worse of both.
 */
function evaluateRetry(step: IssuerStepDefinition, evidence: IssuanceEvidence, credentials: IssuedCredentialRecord[], first: { exchanges: number; credentials: number }) {
  const [rejected, ...retried] = step.expect.codes;
  const attempt = observationOf({ exchanges: evidence.exchanges.slice(0, first.exchanges), ...(evidence.error && evidence.exchanges.length === first.exchanges ? { error: evidence.error } : {}) }, credentials.slice(0, first.credentials));
  const one = evaluateIssuance({ ...step.expect, codes: [rejected] }, attempt);
  if (evidence.exchanges.length === first.exchanges) {
    return { verdict: worst([one.verdict, 'FAIL']), reason: `${one.reason}; no retry was sent${evidence.error ? ` (${evidence.error})` : ''}` };
  }
  const retry = { exchanges: evidence.exchanges.slice(first.exchanges), ...(evidence.error ? { error: evidence.error } : {}) };
  const two = evaluateIssuance({ ...step.expect, codes: retried }, observationOf(retry, credentials.slice(first.credentials)));
  return { verdict: worst([one.verdict, two.verdict]), reason: `first request: ${one.reason}; retry with a fresh c_nonce: ${two.reason}` };
}

/**
 * The issuance options of the grant (issue 20): the adapter's `authenticateSubject` for the authorization code flow,
 * the grant fault, the second offer `token-request.pre-authorized-code-other-offer` needs (for `ICS-02.second`), the
 * declared lifetime of a pre-authorized code, and the run's wait limit.
 */
async function grantOptions(action: IssuanceAction, subject: IssuanceAction['subject'] & string, txCode: boolean, ctx: Context): Promise<Partial<IssueOptions>> {
  const fault = action.faults.find(isGrantFault);
  const lifetime = durationMs(issuerIcsValue(ctx.ics, 'ICS-14.pre_authorized_code'));
  const options: Partial<IssueOptions> = {
    grant: action.grant,
    ...(action.stopAfterAuthorization ? { stopAfterAuthorization: true } : {}),
    ...(fault ? { grantFault: fault } : {}),
    ...(lifetime !== undefined ? { preAuthorizedCodeLifetimeSeconds: lifetime / 1000 } : {}),
    maxWaitSeconds: ctx.maxWaitSeconds ?? 0,
  };
  const authenticate = ctx.adapter.authenticateSubject?.bind(ctx.adapter);
  if (action.grant === 'authorization_code' && authenticate) options.authenticate = (url) => authenticate(url, subject);
  if (fault && grantFaultInfo(fault).otherOffer) {
    const [second] = resolveConfigurations(['ICS-02.second'], ctx.ics);
    const other = await ctx.adapter.createOffer({ subject, configurations: [second], grant: 'pre-authorized_code', byReference: false, txCode });
    options.otherOffer = { offer: other.offer, ...(other.txCode !== undefined ? { txCode: other.txCode } : {}) };
  }
  return options;
}

/**
 * A `credential_identifier` another session's token response issued for the step's configuration: a valid issuance of a
 * second offer for the same subject and grant with `CW-2`, whose token response is read (`identifier-foreign`).
 */
async function foreignCredentialIdentifier(action: IssuanceAction, subject: IssuanceAction['subject'] & string, configurations: string[], txCode: boolean, ctx: Context, state: TestCaseState): Promise<string | undefined> {
  const other = await ctx.adapter.createOffer({ subject, configurations, grant: action.grant, byReference: false, txCode });
  const client = await clientOf('CW-2', ctx, state);
  const evidence = await client.issue({
    offer: other.offer,
    ...(other.txCode !== undefined ? { txCode: other.txCode } : {}),
    credentialConfigurationIds: configurations,
    ...(await grantOptions({ ...action, faults: [] }, subject, txCode, ctx)),
  });
  if (!evidence.token) return undefined;
  try {
    return credentialIdentifierOf(evidence.token, configurations[0] as string);
  } catch {
    return undefined;
  }
}

/**
 * `token-reuse` (issuer harness design section 6.1): sends the request of an earlier issuance step again with one of its
 * artifacts, as the Wallet Unit the action names (default that of the step): its pre-authorized or authorization code
 * at the token endpoint, or its PAR `request_uri` at the authorization endpoint through the adapter.
 */
async function runTokenReuse(
  step: IssuerStepDefinition,
  action: TokenReuseAction,
  record: IssuerStepRecord,
  save: (name: string, content: string) => Promise<void>,
  ctx: Context,
  state: TestCaseState,
): Promise<void> {
  const earlier = state.evidence.get(action.ofStep);
  if (!earlier?.grant || !earlier.metadata) {
    record.reason = `step ${action.ofStep} obtained no ${action.artifact} to reuse${earlier?.error ? ` (${earlier.error})` : ''}`;
    return;
  }
  const unit = action.walletUnit ?? earlier.walletUnit;
  record.walletUnit = unit;
  const client = await clientOf(unit, ctx, state);
  let evidence: IssuanceEvidence;
  if (action.artifact === 'par-request-uri') {
    const authenticate = ctx.adapter.authenticateSubject?.bind(ctx.adapter);
    if (!authenticate) {
      record.reason = 'the adapter cannot authenticate the subject (no authenticateSubject)';
      return;
    }
    evidence = await client.reuseRequestUri(earlier.metadata, earlier.grant, (url) => authenticate(url, 'SUBJ-1'));
  } else if (action.artifact === 'authorization-code' || action.artifact === 'pre-authorized-code') {
    const expected = action.artifact === 'authorization-code' ? 'authorization_code' : 'pre-authorized_code';
    if (earlier.grant.grant !== expected) {
      record.reason = `step ${action.ofStep} ran the ${earlier.grant.grant} grant, not ${expected}`;
      return;
    }
    evidence = await client.redeemAgain(earlier.metadata, earlier.grant);
  } else {
    record.reason = `token-reuse of ${action.artifact} is not implemented yet`;
    return;
  }
  record.exchanges = evidence.exchanges;
  if (evidence.token) record.token = { tokenType: evidence.token.tokenType };
  if (evidence.error) record.error = evidence.error;
  await save('token-reuse.json', `${JSON.stringify({ artifact: action.artifact, ofStep: action.ofStep, walletUnit: unit, grant: evidence.grant, exchanges: evidence.exchanges }, null, 2)}\n`);
  const evaluation = evaluateIssuance(step.expect, { ...observationOf(evidence, []), ...conformanceOf(evidence) });
  record.verdict = evaluation.verdict;
  record.reason = evaluation.reason;
}

/** The `CONF` checks of an issuance step: the authorization response, when the flow had one (`IA_AuthorizationCode_007`). */
function conformanceOf(evidence: IssuanceEvidence): Pick<IssuanceObservation, 'conformance'> {
  const authorization = evidence.grant?.authorization;
  if (!authorization) return {};
  return { conformance: checkAuthorizationResponse(authorization.response, { state: authorization.state, issuer: authorization.authorizationServer }) };
}

/** `OBS-CRED`: every credential the step received through the reference validator, with the suite's trust configuration. */
async function validateCredentials(evidence: IssuanceEvidence, ctx: Context, output?: IssuedOutputOptions, notDeviceBound = false): Promise<IssuedCredentialRecord[]> {
  const trust = ctx.harness.trustStore;
  if (!trust) throw new Error('the reference validator has no trust configuration (no enrolment)');
  const records: IssuedCredentialRecord[] = [];
  for (const issued of evidence.credentials) {
    const configuration = evidence.metadata?.result.credentialIssuer.credential_configurations_supported[issued.credentialConfigurationId] as
      | { vct?: string; doctype?: string; cryptographic_binding_methods_supported?: unknown[] }
      | undefined;
    const base = {
      configuration: issued.credentialConfigurationId,
      format: issued.format,
      credential: issued.credential,
      proofKey: issued.proofKey.publicJwk,
      keyAttestation: issued.keyAttestation,
    };
    const common = {
      trust,
      trustRule: ctx.harness.trustRule,
      issuerEntity: ctx.harness.issuerName,
      proofKeys: [issued.proofKey.publicJwk],
      keyAttestations: [issued.keyAttestation],
      skewSeconds: ISSUER_SKEW_SECONDS,
      requireStatus: true,
      maxStatusListBytes: MAX_STATUS_LIST_BYTES,
      // Issue 27: a configuration the ICS declares not device-bound, or one without cryptographic binding in its
      // metadata, issues credentials bound to no key.
      ...(notDeviceBound || (configuration && !configuration.cryptographic_binding_methods_supported?.length) ? { deviceBound: false } : {}),
      ...(output ? { output } : {}),
    };
    if (issued.format === 'mso_mdoc') {
      // The MSO references the Status List Token in CWT format (ISO/IEC 18013-5 second edition, Token Status List).
      const validation = await validateIssuedMdoc(issued.credential, {
        ...common,
        expectedDocType: configuration?.doctype ?? '',
        fetchStatusList: async (uri) => {
          const response = await ctx.harness.fetch(uri, { headers: { accept: 'application/statuslist+cwt' } });
          return { status: response.status, body: new Uint8Array(await response.arrayBuffer()), contentType: response.headers.get('content-type') };
        },
      });
      records.push({
        ...base,
        valid: validation.valid,
        ...(validation.issuer ? { issuer: validation.issuer } : {}),
        ...(validation.claims ? { claims: validation.claims } : {}),
        ...(validation.pidClaims ? { pidClaims: validation.pidClaims } : {}),
        checks: validation.checks,
      });
      continue;
    }
    if (issued.format !== 'dc+sd-jwt') {
      records.push({ ...base, valid: false, checks: [{ check: 'format', status: 'fail', detail: `the reference validator checks dc+sd-jwt and mso_mdoc only, not ${issued.format}` }] });
      continue;
    }
    const validation = await validateIssuedSdJwtVc(issued.credential, {
      ...common,
      expectedVct: configuration?.vct ? [configuration.vct] : [],
      fetchStatusList: async (uri) => {
        const response = await ctx.harness.fetch(uri, { headers: { accept: 'application/statuslist+jwt' } });
        return { status: response.status, body: await response.text(), contentType: response.headers.get('content-type') };
      },
    });
    records.push({
      ...base,
      valid: validation.valid,
      ...(validation.issuer ? { issuer: validation.issuer } : {}),
      ...(validation.claims ? { claims: validation.claims } : {}),
      checks: validation.checks,
    });
  }
  return records;
}

/** What the evaluators need of the evidence: every exchange with its status and OAuth error, and the checks. */
export function observationOf(evidence: Pick<IssuanceEvidence, 'exchanges' | 'token' | 'error'>, credentials: { checks: CheckResult[] }[], stepChecks?: CheckResult[]): IssuanceObservation {
  return {
    exchanges: evidence.exchanges.map((exchange) => {
      // The authorization endpoint answers with a redirect to the wallet; an error travels in its query (RFC 6749 section 4.1.2.1).
      const redirect = exchange.step === 'authorization' && exchange.response?.headers.location;
      const redirectError = redirect ? (new URL(redirect).searchParams.get('error') ?? undefined) : undefined;
      const error = redirectError ?? (exchange.response && exchange.response.status >= 400 ? oauthErrorOf(exchange.response) : undefined);
      return {
        step: exchange.step,
        ...(exchange.response ? { status: exchange.response.status } : {}),
        ...(error ? { error } : {}),
        ...(exchange.error ? { transportError: exchange.error } : {}),
      };
    }),
    tokenIssued: evidence.token !== undefined,
    credentials: credentials.map((c) => ({ checks: c.checks })),
    ...(stepChecks?.length ? { stepChecks } : {}),
    ...(evidence.error ? { error: evidence.error } : {}),
  };
}

// Issue 26: helpers of the trust-list and change-subject test cases.
/** A test case with an `issuer-event` that changes the subject's data. */
function changesSubject(definition: IssuerTestCaseDefinition): boolean {
  return definition.steps.some((step) => step.run?.kind === 'issuer-event' && step.run.event === 'change-subject');
}

const trustContext = (ctx: Context) => ({ harness: ctx.harness, adapter: ctx.adapter, ics: ctx.ics, namespace: ctx.harness.namespace, ...(ctx.log ? { log: ctx.log } : {}) });

/**
 * Issue 26: runs issuance steps one after another, also when the test cases they belong to run in parallel. The waiting
 * test cases overlap in their waits, not in their issuances: concurrent credential requests are not what they test, and
 * the reference image refuses some of them (`credential_request_denied` "Could not allocate status entry after maximum
 * retries", seen with a dozen issuances in the same second).
 */
// Issue 27: one queue per Provider instance (harness); the instances of the categories issue in parallel.
const issuing = new WeakMap<object, Promise<unknown>>();
function oneAtATime<T>(key: object, task: () => Promise<T>): Promise<T> {
  const run = (issuing.get(key) ?? Promise.resolve()).then(task, task);
  issuing.set(key, run.catch(() => undefined));
  return run;
}
