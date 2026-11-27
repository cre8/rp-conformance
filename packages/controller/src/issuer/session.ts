// Issue 25: the steps of the test cases of DPoP (`PP_WS_SM_TokenBinding`), batch issuance, re-issuance, deferred
// issuance, notification and robustness (`PP_WS_SH_Encoding`, `PP_WS_SH_Encryption`). They run on the session client of
// the issuance client package, which keeps the state later steps of a test case need: the refresh token for the refresh
// grant, the DPoP proof for its replay, the `notification_id` and `transaction_id`. The runner hands a definition to
// this module when one of its steps needs it (`isSessionDefinition`); any other step stays with the runner.
//
// Expected results beyond `ISS`, `REJ` and `INFO` (which the runner's evaluators decide): `CONF` with the named checks
// below, `NOFETCH` from the request log of the Test Status Provider, `UNCHANGED` by checking the status of the
// credential again, and `REJ:<a>|<b>` for a step that accepts either code (catalogue: "invalid_proof or ...").
import {
  type CheckResult,
  type IssuerAdapter,
  type IssuerExpectation,
  type IssuerIcs,
  type IssuerStepDefinition,
  type IssuerTestCaseDefinition,
  isSessionFault,
  sessionFaultInfo,
  ICS_BATCH_SIZE,
  type Verdict,
} from '@eudi-pcaf/core';
import { base64url } from '@eudi-pcaf/forge';
import {
  applyIssuerFault,
  applySessionFault,
  type HttpRequestMessage,
  type SessionClient,
  SessionClient as Client,
  type SessionEvidence,
  type SessionHooks,
  type SessionState,
  walletUnitOf,
} from '@eudi-pcaf/issuer-wallet';
import { jwkThumbprint, validateIssuedSdJwtVc } from '@eudi-pcaf/validator';
import type { WalletUnitId } from '@eudi-pcaf/wallet-provider';
import type { AttestationState } from './attestations';
import type { LifecycleState } from './status';
import { type Evaluation, worst } from '../evaluate';
import { evaluateIssuance } from './evaluate';
import type { IssuerHarness } from './harness';
import { issuerIcsValue, resolveConfigurations, usesTxCode } from './ics';
import { type IssuedCredentialRecord, ISSUER_SKEW_SECONDS, type IssuerStepRecord, observationOf } from './runner';

/** The named `CONF` checks of the session steps. */
export const SESSION_CONF_CHECKS = [
  // PP_WS_SM_TokenBinding_001: the token response has `token_type` `DPoP`, and a JWT access token's `cnf.jkt` is the thumbprint of the DPoP key.
  'token-dpop-bound',
  // PP_WS_IA_Batch_001: as many credentials as proofs, each bound to the key of another proof.
  'batch-size',
  'batch-distinct-keys',
  // PP_WS_IA_Batch_002: the credentials of a batch carry the same claims and the same validity.
  'batch-same-claims',
  'batch-same-validity',
  // PP_WS_IA_Reissuance_003: compared with the credential of the earlier step.
  'reissue-same-claims',
  'reissue-new-salts',
  'reissue-new-status-index',
  'reissue-new-key',
  'reissue-new-validity',
  // PP_WS_IA_Notification_001: the notification endpoint answers with HTTP 2xx (OpenID4VCI 1.0 section 11.2: MUST 2xx,
  // 204 RECOMMENDED; another 2xx is recorded in the check's detail).
  'notification-2xx',
  // PP_WS_IA_Batch_006: the whole batch after exactly one authorization request (one User authentication).
  'single-authentication',
  // PP_WS_IA_Deferred_001: HTTP 202 with `transaction_id` and `interval`, then `issuance_pending`, then the credential.
  'deferred-pending',
] as const;

export type SessionConfCheck = (typeof SESSION_CONF_CHECKS)[number];

/** The paths under which the faults of `PP_WS_SH_Encoding_003` and `_004` point to the Test Status Provider. */
const NOFETCH_PATHS = ['jku', 'x5u', 'kid', 'ca-x-wia-status', 'ca-x-ka-status'];

const MAX_STATUS_LIST_BYTES = 10 << 20;

/** What this module needs of the runner's context. */
export interface SessionContext {
  adapter: IssuerAdapter;
  ics: IssuerIcs;
  harness: IssuerHarness;
}

interface StepState {
  /** The adapter's session of the offer (`setStatus`). */
  sessionId?: string;
  client: SessionClient;
  session: SessionState;
  evidence: SessionEvidence;
  credentials: IssuedCredentialRecord[];
}

/** Per test case (keyed by the runner's state object): the state of each step that ran here. */
const caseStates = new WeakMap<object, Map<number, StepState>>();

/**
 * What the session module reads and writes of the runner's per-test-case state: the status references a
 * `wallet-event` step moved (issue 19, `applyWalletEvent`), and the issuance steps with their adapter session and
 * credentials, which `issuer-event` and `observe-status` (issue 22) read.
 */
interface SharedCaseState {
  attestations?: AttestationState;
  issued?: LifecycleState['issued'];
}

/** The Wallet Unit as the client sees it, with the status references a `wallet-event` of the test case moved. */
function bindingOf(ctx: SessionContext, caseState: object, unit: WalletUnitId) {
  const twp = ctx.harness.twp;
  const moved = (caseState as SharedCaseState).attestations?.status.get(unit);
  const base = walletUnitOf(twp, unit);
  return {
    binding: {
      ...base,
      ...(moved?.wia ? { wia: () => twp.wia(unit, { status: moved.wia! }) } : {}),
      ...(moved?.ka ? { keyAttestation: () => twp.keyAttestation(unit, { status: moved.ka! }) } : {}),
    },
    keyAttestation: (count: number) => twp.keyAttestation(unit, { batchSize: count, ...(moved?.ka ? { status: moved.ka } : {}) }),
    movedUris: [...new Set([moved?.wia?.uri, moved?.ka?.uri].filter((u): u is string => Boolean(u)))],
  };
}

/** Per test case: the record of every step so far, whoever ran it. */
const caseRecords = new WeakMap<object, IssuerStepRecord[]>();

/** The runner notes each step record here, so a later step can tell whether a step it depends on passed. */
export function noteSessionStep(caseState: object, record: IssuerStepRecord): IssuerStepRecord {
  caseRecords.set(caseState, [...(caseRecords.get(caseState) ?? []), record]);
  return record;
}

/** Actions that change the state later steps observe: a step after one of them that did not pass cannot be judged. */
const EVENT_ACTIONS = new Set(['wallet-event', 'issuer-event', 'trust-list']);

/** Why the step cannot be judged: a step it depends on (its `ofStep`, or an earlier event) did not pass. */
function unmetDependency(step: IssuerStepDefinition, records: IssuerStepRecord[]): string | undefined {
  const run = step.run!;
  const ofStep = 'ofStep' in run ? (run as { ofStep: number }).ofStep : undefined;
  const of = ofStep !== undefined ? records.find((r) => r.step === ofStep) : undefined;
  if (of && of.verdict !== 'PASS') return `step ${ofStep}, whose result this step uses, is ${of.verdict}`;
  const event = records.find((r) => EVENT_ACTIONS.has(r.action) && r.verdict !== 'PASS');
  if (event) return `step ${event.step} (${event.action}) is ${event.verdict}: ${event.reason}`;
  return undefined;
}

const SESSION_ARTIFACTS = new Set(['refresh-token', 'dpop-proof', 'transaction-id']);

/**
 * The areas of issue 25 whose definitions this module runs. Chosen by test case ID rather than by step shape, so the
 * `CONF`, `UNCHANGED` or `wallet-event` steps of other areas stay with the runner and their own evaluators.
 */
const SESSION_AREAS = /^(?:PP|AP)_WS_(?:SM_TokenBinding|IA_Batch|IA_Reissuance|IA_Deferred|IA_Notification|SH_Encoding|SH_Encryption)_\d{3}/;

/** A definition of issue 25. */
export const isSessionDefinition = (definition: IssuerTestCaseDefinition) => SESSION_AREAS.test(definition.id);

/**
 * The steps of a session definition this module runs: every issuance step (so later steps find its session), the
 * notification steps and the repeated requests of a session. `wallet-event` (issue 19) and `issuer-event` (issue 22)
 * stay with the runner; this module reads what they leave in the shared state of the test case.
 */
export const handlesSessionStep = (definition: IssuerTestCaseDefinition, step: IssuerStepDefinition) =>
  isSessionDefinition(definition) &&
  (step.run?.kind === 'issuance' ||
    step.run?.kind === 'notification' ||
    (step.run?.kind === 'token-reuse' && SESSION_ARTIFACTS.has(step.run.artifact)));

/** The longest a step may wait in this run (seconds): `ISSUER_MAX_WAIT_SECONDS`, default 600. */
const maxWaitSeconds = () => Number(process.env.ISSUER_MAX_WAIT_SECONDS ?? 600);

const wait = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** An ISO 8601 duration of the ICS in seconds (`PT5M` → 300); NaN when not declared. */
function issuerIcsSeconds(ics: IssuerIcs, key: string): number {
  const match = /^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$/.exec(issuerIcsValue(ics, key) ?? '');
  return match ? Number(match[1] ?? 0) * 3600 + Number(match[2] ?? 0) * 60 + Number(match[3] ?? 0) : Number.NaN;
}

/**
 * Applicability beyond the profiles: a fault that needs a DPoP server nonce does not apply to a Provider that declares
 * none (ICS-13.dpop_nonce No), since `P-DPN` also stands for the nonce endpoint.
 */
export function sessionApplicability(definition: IssuerTestCaseDefinition, ics: IssuerIcs): string[] {
  const needsNonce = definition.steps.some((s) => s.run?.kind === 'issuance' && s.run.faults.some((f) => isSessionFault(f) && sessionFaultInfo(f).requiresDpopNonce));
  return needsNonce && /^no$/i.test(issuerIcsValue(ics, 'ICS-13.dpop_nonce') ?? '') ? ['ICS-13.dpop_nonce No: the Provider uses no DPoP server nonce'] : [];
}

const batchSizeOf = (ics: IssuerIcs) => Number(issuerIcsValue(ics, 'ICS-08.batch_size') ?? 1);

/** Runs one step of a session definition into `record`. */
export async function runSessionStep(
  step: IssuerStepDefinition,
  index: number,
  record: IssuerStepRecord,
  save: (name: string, content: string) => Promise<void>,
  ctx: SessionContext,
  caseState: object,
): Promise<void> {
  const states = caseStates.get(caseState) ?? new Map<number, StepState>();
  caseStates.set(caseState, states);
  const run = step.run!;
  const dependency = unmetDependency(step, caseRecords.get(caseState) ?? []);
  if (dependency) {
    record.verdict = 'INCONCLUSIVE';
    record.reason = `not executed: ${dependency}`;
    return;
  }
  const started = new Date();
  let current: StepState | undefined;
  let notification: { status?: number } | undefined;
  let compareWith: StepState | undefined;

  if (run.kind === 'issuance') {
    const unit = (run.walletUnit ?? 'CW-1') as WalletUnitId;
    const subject = run.subject ?? 'SUBJ-1';
    record.walletUnit = unit;
    record.subject = subject;
    const fault = run.faults[0];
    if (fault) record.fault = fault;
    const authenticate = ctx.adapter.authenticateSubject?.bind(ctx.adapter);
    if (run.grant === 'authorization_code' && !authenticate) {
      record.reason = 'the adapter cannot authenticate the subject (no authenticateSubject)';
      return;
    }
    const twp = ctx.harness.twp;
    const bound = bindingOf(ctx, caseState, unit);
    let binding = bound.binding;
    let hooks: SessionHooks = {};
    let credential: Parameters<SessionClient['credential']>[2] = {};
    let noDpopRetry = false;
    if (fault && isSessionFault(fault)) {
      const applied = applySessionFault(fault, { batchSize: batchSizeOf(ctx.ics) });
      hooks = applied.hooks;
      credential = applied.credential;
      noDpopRetry = applied.noDpopRetry ?? false;
    } else if (fault) {
      if (bound.movedUris.length) throw new Error(`a step after a wallet-event applies no fault of the points wia, ka or proof, not ${fault}`);
      const applied = await applyIssuerFault(fault as never, { twp, unit });
      binding = applied.unit;
      hooks = applied.hooks;
    }
    const configurations = resolveConfigurations(run.configurations, ctx.ics);
    if (run.deferred && !ctx.adapter.completeDeferred) {
      record.reason = 'the adapter cannot complete a deferred issuance (no completeDeferred hook)';
      return;
    }
    const offer = await ctx.adapter.createOffer({
      subject,
      configurations,
      grant: run.grant,
      byReference: run.offerByReference ?? false,
      txCode: usesTxCode(ctx.ics),
      ...(run.deferred ? { deferred: true } : {}),
    });
    record.offer = { sessionId: offer.sessionId, offer: offer.offer, byReference: run.offerByReference ?? false, txCode: offer.txCode !== undefined, configurations };
    const client = await Client.create(binding, bound.keyAttestation, { allowInsecureUrls: true, hooks, noDpopRetry });
    const evidence = Client.newEvidence(unit);
    let session: SessionState | undefined;
    try {
      session = await client.start(offer.offer, evidence, configurations[0]);
      if (run.grant === 'authorization_code') await client.authorizationCode(session, evidence, (url) => authenticate!(url, subject));
      else await client.token(session, evidence, offer.txCode);
      const info = fault && isSessionFault(fault) ? sessionFaultInfo(fault) : undefined;
      if (info?.waitsAfterExpiry !== undefined) {
        // `access-token.expired`: the Provider enforces the token lifetime, so the step waits it out (expires_in, plus the
        // declared T_skew, capped at the catalogue's 5 minutes, plus the fault's margin).
        const expiresIn = Number(session.tokenResponse?.expires_in ?? issuerIcsSeconds(ctx.ics, 'ICS-14.access_token'));
        const skew = Math.min(issuerIcsSeconds(ctx.ics, 'ICS-14.T_skew') || ISSUER_SKEW_SECONDS, ISSUER_SKEW_SECONDS);
        const seconds = expiresIn + skew + info.waitsAfterExpiry;
        if (!Number.isFinite(seconds) || seconds > maxWaitSeconds()) {
          record.reason = `the step would wait ${seconds} s (expires_in ${expiresIn} s, T_skew ${skew} s, ${info.waitsAfterExpiry} s) before the credential request, more than this run allows (ISSUER_MAX_WAIT_SECONDS ${maxWaitSeconds()} s)`;
          record.verdict = 'INCONCLUSIVE';
          record.exchanges = evidence.exchanges;
          return;
        }
        await wait(seconds * 1000);
        record.reason = `waited ${seconds} s after the token response (expires_in ${expiresIn} s, T_skew ${skew} s, margin ${info.waitsAfterExpiry} s)`;
      }
      if (!run.stopAfterToken) {
        const completed = new Set<string>();
        let other: StepState | undefined;
        if (info?.needsOtherSession) {
          other = [...states.values()].reverse().find((s) => s.session?.accessToken && s.evidence.walletUnit !== unit);
          if (!other) throw new Error(`${fault} needs an earlier step of another Wallet Unit with an access token`);
        }
        await client.credential(session, evidence, {
          proofs: credential.proofs ?? (run.batchSize === ICS_BATCH_SIZE ? batchSizeOf(ctx.ics) : (run.batchSize ?? 1)),
          ...(credential.keys ? { keys: credential.keys } : {}),
          ...(credential.keyIndex ? { keyIndex: credential.keyIndex } : {}),
          encryption: run.encryption ?? false,
          followDeferred: !other,
          // The adapter completes the deferred issuance once a poll has answered `issuance_pending`.
          onPending: async (transactionId) => {
            if (!completed.has(transactionId)) {
              completed.add(transactionId);
              await ctx.adapter.completeDeferred?.(transactionId, subject);
            }
          },
        });
        if (other && session.transactionId) {
          await other.client.pollDeferred(other.session, evidence, { interval: 0, maxPolls: 1, sleep: async () => {}, encryption: false, transactionId: session.transactionId });
        }
      }
    } catch (error) {
      evidence.error = (error as Error).message;
    }
    current = { sessionId: offer.sessionId, client, session: session!, evidence, credentials: [] };
  } else if (run.kind === 'token-reuse' || run.kind === 'notification') {
    const prior = states.get(run.ofStep);
    if (!prior?.session) {
      record.reason = `step ${run.ofStep} left no session to continue`;
      return;
    }
    // `PP_WS_IA_Reissuance_002_UF`: the refresh token of `CW-1` presented by another Wallet Unit, with its own WIA, PoP
    // and a DPoP key of its own (RFC 9449 section 5: a confidential client's refresh token is bound to the client).
    const otherUnit = run.kind === 'token-reuse' && run.walletUnit && run.walletUnit !== prior.evidence.walletUnit ? run.walletUnit : undefined;
    record.walletUnit = otherUnit ?? prior.evidence.walletUnit;
    const fault = run.kind === 'notification' ? run.faults[0] : run.faults?.[0];
    if (fault) record.fault = fault;
    let hooks: SessionHooks = fault ? applySessionFault(fault, { batchSize: batchSizeOf(ctx.ics) }).hooks : {};
    const session: SessionState = { ...prior.session, cNonce: undefined, notificationIds: [...prior.session.notificationIds], dpopJtis: [...prior.session.dpopJtis] };
    const evidence = Client.newEvidence(record.walletUnit);
    if (prior.evidence.metadata) evidence.metadata = prior.evidence.metadata;
    if (run.kind === 'token-reuse' && run.artifact === 'dpop-proof') {
      // RFC 9449 section 11.1: the DPoP proof of the earlier credential request, sent again as it was.
      const earlier = prior.evidence.exchanges.filter((e) => e.step === 'credential').at(-1)?.request;
      const proof = earlier && Object.entries(earlier.headers).find(([k]) => k.toLowerCase() === 'dpop')?.[1];
      if (!proof) {
        record.reason = `step ${run.ofStep} sent no credential request with a DPoP proof`;
        return;
      }
      hooks = { request: (s, r: HttpRequestMessage) => (s === 'credential' ? { ...r, headers: { ...withoutHeader(r.headers, 'dpop'), DPoP: proof } } : r) };
    }
    const moved = bindingOf(ctx, caseState, record.walletUnit as WalletUnitId);
    const client = otherUnit
      ? await Client.create(moved.binding, moved.keyAttestation, { allowInsecureUrls: true, hooks })
      : await prior.client.with({ hooks, unit: moved.binding, keyAttestation: moved.keyAttestation });
    try {
      if (run.kind === 'notification') {
        const response = await client.notify(session, evidence, run.event);
        notification = { status: response.status };
      } else if (run.artifact === 'refresh-token') {
        await client.refresh(session, evidence);
        // A faulty refresh request is judged by its own answer: a token issued for it is the failure.
        if (!fault && !otherUnit) await client.credential(session, evidence, {});
        compareWith = prior;
      } else if (run.artifact === 'dpop-proof') {
        await client.credential(session, evidence, {});
      } else {
        await client.pollDeferred(session, evidence, { interval: 0, maxPolls: 1, sleep: async () => {}, encryption: false, ...(prior.session.transactionId ? { transactionId: prior.session.transactionId } : {}) });
      }
    } catch (error) {
      evidence.error = (error as Error).message;
    }
    current = { client, session, evidence, credentials: [] };
  } else {
    record.reason = `the step action ${run.kind} is not implemented yet`;
    return;
  }

  const { evidence } = current;
  record.exchanges = evidence.exchanges;
  if (evidence.token) record.token = { tokenType: evidence.token.tokenType };
  if (evidence.error) record.error = evidence.error;
  current.credentials = await validateSessionCredentials(evidence, ctx);
  record.credentials = current.credentials;
  states.set(index, current);
  // Issue 22's `issuer-event` and `observe-status` read the issuance steps of the test case from the shared state.
  if (run.kind === 'issuance' && current.sessionId) {
    (caseState as SharedCaseState).issued?.set(index, { sessionId: current.sessionId, credentials: evidence.credentials });
  }
  for (const [i, credential] of record.credentials.entries()) await save(`credential-${i + 1}.txt`, credential.credential);
  await save(
    'session.json',
    `${JSON.stringify({ offer: record.offer, exchanges: evidence.exchanges.map(truncateExchange), plaintext: evidence.plaintext, notificationId: evidence.notificationId, transactionId: evidence.transactionId, deferred: evidence.deferred }, null, 2)}\n`,
  );

  const observation = observationOf(evidence, current.credentials);
  const evaluations: Evaluation[] = [];
  for (const code of step.expect.codes) {
    if (code === 'CONF') evaluations.push(evaluateConf(step.expect, current, { notification, compareWith, ics: ctx.ics }));
    else if (code === 'NOFETCH') evaluations.push(evaluateNoFetch(ctx.harness, started));
    else if (code === 'UNCHANGED') evaluations.push(await evaluateUnchanged(run.kind === 'issuance' ? current : (states.get((run as { ofStep: number }).ofStep) ?? current), ctx));
    else if (code === 'INFO') evaluations.push(describeInfo(observation, current));
    else if (code.startsWith('REJ:') && code.includes('|')) {
      const alternatives = code.slice(4).split('|').map((c) => evaluateIssuance({ codes: [`REJ:${c}`], text: '' }, observation));
      evaluations.push(alternatives.find((e) => e.verdict === 'PASS') ?? { verdict: alternatives[0].verdict, reason: `${alternatives.map((e) => e.reason).join(' / ')}` });
    } else {
      // The named checks of a step with `CONF` are the session's, not checks of the reference validator on the credential.
      const { checks, ...rest } = step.expect;
      evaluations.push(evaluateIssuance({ ...rest, ...(step.expect.codes.includes('CONF') ? {} : checks ? { checks } : {}), codes: [code] }, observation));
    }
  }
  record.verdict = worst(evaluations.map((e) => e.verdict)) as Verdict;
  record.reason = evaluations.map((e) => e.reason).join('; ');
  const movedUris = record.walletUnit ? bindingOf(ctx, caseState, record.walletUnit as WalletUnitId).movedUris : [];
  if (movedUris.length) {
    const fetched = movedUris.reduce((n, uri) => n + ctx.harness.status.requestsFor(uri, started).length, 0);
    record.reason += `; the Provider requested the status list the wallet-event step serves ${fetched} time(s) during the step`;
  }
}

const withoutHeader = (headers: Record<string, string>, name: string) => Object.fromEntries(Object.entries(headers).filter(([k]) => k.toLowerCase() !== name));

/** Bodies of more than 4 KiB (the oversized and deeply nested requests) are shortened in the evidence file. */
function truncateExchange<T extends { request: HttpRequestMessage }>(exchange: T): T {
  const body = exchange.request.body;
  if (!body || body.length <= 4096) return exchange;
  return { ...exchange, request: { ...exchange.request, body: `${body.slice(0, 2048)}… (${body.length} characters)` } };
}

/** `OBS-CRED` for the credentials of a session step: holder binding to any proof key of the request. */
async function validateSessionCredentials(evidence: SessionEvidence, ctx: SessionContext): Promise<IssuedCredentialRecord[]> {
  const trust = ctx.harness.trustStore;
  if (!trust) throw new Error('the reference validator has no trust configuration (no enrolment)');
  const records: IssuedCredentialRecord[] = [];
  for (const issued of evidence.credentials) {
    const configuration = evidence.metadata?.result.credentialIssuer.credential_configurations_supported[issued.credentialConfigurationId] as { vct?: string } | undefined;
    const validation = await validateIssuedSdJwtVc(issued.credential, {
      trust,
      trustRule: ctx.harness.trustRule,
      issuerEntity: ctx.harness.issuerName,
      expectedVct: configuration?.vct ? [configuration.vct] : [],
      proofKeys: issued.proofKeys.map((k) => k.publicJwk),
      keyAttestations: [issued.keyAttestation],
      skewSeconds: ISSUER_SKEW_SECONDS,
      requireStatus: true,
      maxStatusListBytes: MAX_STATUS_LIST_BYTES,
      fetchStatusList: async (uri) => {
        const response = await ctx.harness.fetch(uri, { headers: { accept: 'application/statuslist+jwt' } });
        return { status: response.status, body: await response.text(), contentType: response.headers.get('content-type') };
      },
    });
    records.push({
      configuration: issued.credentialConfigurationId,
      format: issued.format,
      credential: issued.credential,
      proofKey: issued.proofKey.publicJwk,
      keyAttestation: issued.keyAttestation,
      valid: validation.valid,
      ...(validation.issuer ? { issuer: validation.issuer } : {}),
      ...(validation.claims ? { claims: validation.claims } : {}),
      checks: validation.checks,
    });
  }
  return records;
}

// ------------------------------------------------------------------------------------------------ CONF checks

/** The issuer-signed payload and the salts of the disclosures of an SD-JWT VC. */
function decodeSdJwt(credential: string): { payload: Record<string, unknown>; salts: string[]; disclosed: Record<string, unknown> } {
  const [jwt, ...disclosures] = credential.split('~');
  const payload = base64url.decodeJson(jwt.split('.')[1] ?? '') as Record<string, unknown>;
  const salts: string[] = [];
  const disclosed: Record<string, unknown> = {};
  for (const disclosure of disclosures.filter(Boolean)) {
    const value = base64url.decodeJson(disclosure) as unknown[];
    salts.push(String(value[0]));
    if (value.length === 3) disclosed[String(value[1])] = value[2];
    else disclosed[`[] ${JSON.stringify(value[1])}`] = value[1];
  }
  return { payload, salts, disclosed };
}

const VALIDITY = ['iat', 'nbf', 'exp'] as const;
const PER_CREDENTIAL = new Set(['cnf', 'status', '_sd', '_sd_alg', ...VALIDITY]);

/** A value without the digests of selective disclosure (`_sd`, `...`), which are salted per credential. */
function withoutDigests(value: unknown): unknown {
  if (Array.isArray(value)) return value.filter((v) => !(v && typeof v === 'object' && '...' in (v as object))).map(withoutDigests);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as object).filter(([k]) => k !== '_sd' && k !== '_sd_alg').map(([k, v]) => [k, withoutDigests(v)]));
  }
  return value;
}

/** What a credential states about the subject: issuer-signed claims other than binding, status and validity, and the disclosed ones. */
function subjectClaims(credential: string) {
  const { payload, disclosed } = decodeSdJwt(credential);
  const signed = Object.fromEntries(Object.entries(payload).filter(([k]) => !PER_CREDENTIAL.has(k)));
  return canonical(withoutDigests({ ...signed, ...disclosed }));
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value as object)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical((value as Record<string, unknown>)[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

const cnfOf = (credential: string) => ((decodeSdJwt(credential).payload.cnf as { jwk?: JsonWebKey } | undefined)?.jwk);
const statusOf = (credential: string) => (decodeSdJwt(credential).payload.status as { status_list?: { idx?: number; uri?: string } } | undefined)?.status_list;
const validityOf = (credential: string) => {
  const { payload } = decodeSdJwt(credential);
  return Object.fromEntries(VALIDITY.map((k) => [k, payload[k]])) as Record<(typeof VALIDITY)[number], number | undefined>;
};

/** ICS-16.timestamp_precision in seconds (`PT1H` → 3600), 0 when not declared. */
const precisionSeconds = (ics: IssuerIcs) => issuerIcsSeconds(ics, 'ICS-16.timestamp_precision') || 0;

function evaluateConf(
  expectation: IssuerExpectation,
  state: StepState,
  extra: { notification?: { status?: number }; compareWith?: StepState; ics: IssuerIcs },
): Evaluation {
  const checks = (expectation.checks ?? []) as SessionConfCheck[];
  if (checks.length === 0) return { verdict: 'INCONCLUSIVE', reason: 'CONF names no check' };
  const credentials = state.credentials.map((c) => c.credential);
  const results: CheckResult[] = [];
  const record = (check: string, ok: boolean, detail: string) => results.push({ check: check as never, status: ok ? 'pass' : 'fail', detail });
  const needCredentials = () => {
    if (credentials.length === 0) throw new Error(`no credential was issued${state.evidence.error ? ` (${state.evidence.error})` : ''}`);
  };
  try {
    for (const check of checks) {
      switch (check) {
        case 'token-dpop-bound': {
          const token = state.evidence.token;
          if (!token) throw new Error(`no access token was issued${state.evidence.error ? ` (${state.evidence.error})` : ''}`);
          const expected = jwkThumbprint(state.client.dpopKey.publicJwk);
          let jkt: unknown;
          try {
            jkt = (base64url.decodeJson(token.accessToken.split('.')[1] ?? '') as { cnf?: { jkt?: unknown } }).cnf?.jkt;
          } catch {
            jkt = undefined;
          }
          const typeOk = token.tokenType === 'DPoP';
          const jktOk = jkt === undefined || jkt === expected;
          record(check, typeOk && jktOk, `token_type ${token.tokenType}; ${jkt === undefined ? 'opaque access token (no cnf.jkt to compare)' : `cnf.jkt ${String(jkt)}${jktOk ? ' is' : ' is not'} the thumbprint ${expected} of the DPoP key`}`);
          break;
        }
        case 'batch-size': {
          const sent = state.evidence.exchanges.filter((e) => e.step === 'credential').at(-1)?.request.body;
          const proofs = (JSON.parse(sent ?? '{}') as { proofs?: { jwt?: unknown[] } }).proofs?.jwt?.length ?? 0;
          record(check, credentials.length === proofs && proofs > 0, `${proofs} proof(s) sent, ${credentials.length} credential(s) issued`);
          break;
        }
        case 'batch-distinct-keys': {
          needCredentials();
          const keys = credentials.map((c) => (cnfOf(c) ? jwkThumbprint(cnfOf(c)!) : 'none'));
          const proofKeys = new Set(state.evidence.credentials[0]?.proofKeys.map((k) => jwkThumbprint(k.publicJwk)));
          const distinct = new Set(keys).size === keys.length;
          const fromProofs = keys.every((k) => proofKeys.has(k));
          record(check, distinct && fromProofs, `cnf keys ${keys.join(', ')}: ${distinct ? 'distinct' : 'not distinct'}, ${fromProofs ? 'each the key of a proof' : 'not all keys of the proofs'}`);
          break;
        }
        case 'batch-same-claims': {
          needCredentials();
          const all = new Set(credentials.map(subjectClaims));
          record(check, all.size === 1, all.size === 1 ? `the ${credentials.length} credentials state the same claims` : `the credentials state ${all.size} different sets of claims`);
          break;
        }
        case 'batch-same-validity': {
          needCredentials();
          const all = new Set(credentials.map((c) => JSON.stringify(validityOf(c))));
          record(check, all.size === 1, `validity ${[...all].join(' / ')}`);
          break;
        }
        case 'reissue-same-claims':
        case 'reissue-new-salts':
        case 'reissue-new-status-index':
        case 'reissue-new-key':
        case 'reissue-new-validity': {
          needCredentials();
          const original = extra.compareWith?.credentials[0]?.credential;
          if (!original) throw new Error('no credential of the earlier step to compare with');
          const fresh = credentials[0];
          if (check === 'reissue-same-claims') record(check, subjectClaims(fresh) === subjectClaims(original), 'claims compared with the original credential');
          if (check === 'reissue-new-salts') {
            const old = new Set(decodeSdJwt(original).salts);
            const shared = decodeSdJwt(fresh).salts.filter((s) => old.has(s));
            record(check, shared.length === 0, shared.length ? `${shared.length} salt(s) reused` : 'every salt is new');
          }
          if (check === 'reissue-new-status-index') {
            const [a, b] = [statusOf(original), statusOf(fresh)];
            record(check, Boolean(b) && (a?.idx !== b?.idx || a?.uri !== b?.uri), `status index ${String(a?.idx)} → ${String(b?.idx)}`);
          }
          if (check === 'reissue-new-key') {
            const [a, b] = [cnfOf(original), cnfOf(fresh)];
            record(check, Boolean(a && b) && jwkThumbprint(a!) !== jwkThumbprint(b!), 'cnf key compared with the original credential');
          }
          if (check === 'reissue-new-validity') {
            const [a, b] = [validityOf(original), validityOf(fresh)];
            const later = (b.iat ?? 0) > (a.iat ?? 0) && (b.exp ?? 0) > (a.exp ?? 0);
            const precision = precisionSeconds(extra.ics);
            const samePeriod = (b.iat ?? 0) === (a.iat ?? 0) && (b.exp ?? 0) === (a.exp ?? 0);
            const withinPrecision = samePeriod && precision > 0 && Math.floor(Date.now() / 1000) - (a.iat ?? 0) < precision;
            record(
              check,
              later || withinPrecision,
              `iat ${a.iat} → ${b.iat}, exp ${a.exp} → ${b.exp}${withinPrecision ? ` (the same period: both issued within the declared timestamp precision ICS-16 of ${precision} s)` : ''}`,
            );
          }
          break;
        }
        case 'single-authentication': {
          const authorizations = state.evidence.exchanges.filter((e) => e.step === 'authorization').length;
          record(check, authorizations === 1 && credentials.length > 0, `${authorizations} authorization request(s) for ${credentials.length} credential(s)`);
          break;
        }
        case 'deferred-pending': {
          const deferred = state.evidence.deferred;
          const accepted = state.evidence.exchanges.find((e) => e.step === 'credential' && e.response?.status === 202);
          const ok = Boolean(accepted && state.evidence.transactionId && deferred?.interval !== undefined && deferred.pending > 0 && credentials.length > 0);
          record(
            check,
            ok,
            `credential request ${accepted ? 'HTTP 202' : 'not deferred'}, transaction_id ${state.evidence.transactionId ? 'present' : 'absent'}, interval ${String(deferred?.interval)}, ${deferred?.polls ?? 0} poll(s) of which ${deferred?.pending ?? 0} issuance_pending, ${credentials.length} credential(s)`,
          );
          break;
        }
        case 'notification-2xx': {
          const status = extra.notification?.status;
          const ok = status !== undefined && status >= 200 && status < 300;
          record(check, ok, `the notification endpoint answered HTTP ${String(status ?? 'nothing')}${ok && status !== 204 ? ' (a 2xx other than the RECOMMENDED 204; recorded)' : ''}`);
          break;
        }
        default:
          throw new Error(`unknown CONF check ${String(check)}`);
      }
    }
  } catch (error) {
    return { verdict: 'FAIL', reason: (error as Error).message };
  }
  const failed = results.filter((r) => r.status === 'fail');
  return {
    verdict: failed.length ? 'FAIL' : 'PASS',
    reason: results.map((r) => `${r.check} ${r.status === 'pass' ? 'passed' : 'failed'} (${r.detail})`).join('; '),
  };
}

/** `NOFETCH`: the Test Status Provider logged no request for a URL that a fault of the step pointed to. */
function evaluateNoFetch(harness: IssuerHarness, since: Date): Evaluation {
  const fetched = harness.status.log.filter((entry) => new Date(entry.at) >= since && NOFETCH_PATHS.includes(new URL(entry.url).pathname.split('/')[1] ?? ''));
  return fetched.length
    ? { verdict: 'FAIL', reason: `the Provider fetched ${fetched.map((e) => e.url).join(', ')}` }
    : { verdict: 'PASS', reason: 'the Test Status Provider logged no request for a URL the fault pointed to' };
}

/** `UNCHANGED`: the credentials of the step are still valid in the status list the Provider publishes now. */
async function evaluateUnchanged(state: StepState, ctx: SessionContext): Promise<Evaluation> {
  if (state.credentials.length === 0) return { verdict: 'INCONCLUSIVE', reason: 'no credential to observe' };
  const again = await validateSessionCredentials(state.evidence, ctx);
  const failed = again.flatMap((c) => c.checks.filter((r) => r.check.startsWith('status') && r.status === 'fail'));
  return failed.length
    ? { verdict: 'FAIL', reason: `the status changed: ${failed.map((r) => `${r.check} (${r.detail ?? ''})`).join('; ')}` }
    : { verdict: 'PASS', reason: 'the credential is still valid in the status list the Provider publishes' };
}

/** `INFO`: what the Provider did, recorded. */
function describeInfo(observation: ReturnType<typeof observationOf>, state: StepState): Evaluation {
  const end = observation.exchanges.at(-1);
  if (state.credentials.length) {
    const keys = state.credentials.map((c) => {
      const jwk = cnfOf(c.credential);
      return jwk ? jwkThumbprint(jwk) : 'none';
    });
    return { verdict: 'PASS', reason: `recorded: the Provider issued ${keys.length} credential(s), bound to ${new Set(keys).size} distinct key(s)` };
  }
  return { verdict: 'PASS', reason: `recorded: no credential; ${end ? `${end.step} HTTP ${end.status ?? 'none'}${end.error ? ` error ${end.error}` : ''}` : 'no request'}` };
}
