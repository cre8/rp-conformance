// The lifecycle steps of the issuer suite (issuer harness design sections 6.1 and 6.3): `issuer-event` (the adapter's
// `setStatus`), `observe-status` (`OBS-SL`: polling the status lists the Provider publishes) and `present` (a credential
// the Provider issued, presented to the reference Relying Party), with the evaluators of `REVOKED(t)`, `UNCHANGED`,
// `CONF` over a published list, `ACC` and `REJ` of a presentation.
import {
  type CheckResult,
  durationMs,
  type IssuerEventAction,
  type IssuerExpectation,
  type IssuerExpectationCode,
  type ObserveStatusAction,
  type PresentAction,
  type TestSubject,
  type Verdict,
} from '@eudi-pcaf/core';
import { defaultQueries, issueRegistrationCertificate } from '@eudi-pcaf/forge';
import type { IssuedCredential } from '@eudi-pcaf/issuer-wallet';
import { ReferenceRelyingParty, type ReferenceRpResult } from '@eudi-pcaf/reference-rp';
import {
  evaluatePublishedStatus,
  type FetchedVersion,
  type MatchedIssuer,
  type PublishedCheckResult,
  readPublishedVersion,
  signerChainOfIssued,
  STATUS_LIST_MEDIA_TYPES,
  type StatusListFormat,
  type StatusReference,
  statusReferenceOfIssued,
} from '@eudi-pcaf/validator';
import { ConformanceWallet } from '@eudi-pcaf/wallet';
import { type Evaluation, worst } from '../evaluate';
import type { IssuerHarness } from './harness';
import { issuerIcsValue } from './ics';

/** Upper bound of a decompressed status list the harness reads (as the runner's `OBS-CRED`). */
const MAX_STATUS_LIST_BYTES = 10 << 20;
/** Clock tolerance of the publication checks: the catalogue's cap of `T_skew` (section 3.5). */
const SKEW_SECONDS = 300;
/** Status values of Token Status List section 7.1. */
const VALID = 0;
const INVALID = 1;

/** What a step of a test case left for later steps: the credentials it issued and when an event happened. */
export interface LifecycleState {
  /** Issuance steps (1-based) with the adapter's session and the credentials with their proof keys. */
  issued: Map<number, { sessionId: string; credentials: IssuedCredential[] }>;
  /** `issuer-event` steps (1-based) with the time the adapter reported the event done (`OBS-ADM`). */
  events: Map<number, { at: Date; status: string }>;
  /** Issue 26: subjects whose data an `issuer-event` changed, with the subject whose data they now have (`SM_Revocation_008`). */
  subjects?: Map<string, string>;
}

export const newLifecycleState = (): LifecycleState => ({ issued: new Map(), events: new Map(), subjects: new Map() });

/** One credential's status in one poll, as the report keeps it (design section 6.3: every version with `iat`, `exp`). */
export interface PolledStatus {
  at: string;
  uri: string;
  idx: number;
  /** HTTP status of the poll. */
  status?: number;
  iat?: number;
  exp?: number;
  ttl?: number;
  /** The status value at `idx` (0 valid, 1 invalid, 2 suspended). */
  value?: number;
  error?: string;
  /** The response headers, kept for the first poll (`sl-cache`, `sl-anonymous`, `sl-uri-privacy`). */
  headers?: Record<string, string>;
}

export interface ObservedCredential {
  step: number;
  configuration: string;
  format: string;
  reference?: StatusReference;
  polls: PolledStatus[];
  /** The publication checks over the first poll (and `sl-continuity` over every poll). */
  checks: PublishedCheckResult[];
}

/** What an `observe-status` step saw. */
export interface StatusObservation {
  window: { from: string; until: string; intervalMs: number; t: string };
  /** The `issuer-event` the window counts from, if any. */
  event?: { step: number; at: string; status: string };
  credentials: ObservedCredential[];
}

export interface LifecycleContext {
  harness: IssuerHarness;
  ics: Parameters<typeof issuerIcsValue>[0];
  harnessHost: string;
  log?: (line: string) => void;
}

/**
 * The window of an `observe-status` step in milliseconds: an ISO 8601 duration, `T_rev` or `T_chain` (their ICS values,
 * ICS-06.T_rev and ICS-07.T_chain), or `exp`, which the runner turns into "until the first version's `exp` has passed".
 */
export function windowMs(t: string, ics: LifecycleContext['ics']): number | 'exp' {
  if (t === 'exp') return 'exp';
  const declared = t === 'T_rev' ? issuerIcsValue(ics, 'ICS-06.T_rev') : t === 'T_chain' ? issuerIcsValue(ics, 'ICS-07.T_chain') : t;
  const ms = durationMs(declared);
  if (ms === undefined) throw new Error(`the ICS declares no duration for ${t} (${declared ?? 'nothing'})`);
  return ms;
}

/** `OBS-SL` polling interval (design section 6.3): `min(t / 20, 30 s)`, at least one second. */
export const pollIntervalMs = (window: number) => Math.max(1000, Math.min(window / 20, 30_000));

/** The formats in which the Provider declares it serves its status lists (ICS-05.token_formats; default JWT). */
export function declaredFormats(ics: LifecycleContext['ics']): StatusListFormat[] {
  const value = (issuerIcsValue(ics, 'ICS-05.token_formats') ?? 'jwt').toLowerCase();
  return (['jwt', 'cwt'] as const).filter((format) => value.includes(format));
}

const formatOfCredential = (format: string): StatusListFormat => (format === 'mso_mdoc' ? 'cwt' : 'jwt');
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** An anonymous GET of a status list URI with the `Accept` of a format, as a Relying Party sends it. */
async function fetchVersion(harness: IssuerHarness, uri: string, format: StatusListFormat): Promise<FetchedVersion> {
  const at = new Date();
  try {
    const response = await harness.fetch(uri, { headers: { accept: STATUS_LIST_MEDIA_TYPES[format] }, signal: AbortSignal.timeout(10_000) });
    const bytes = new Uint8Array(await response.arrayBuffer());
    const contentType = response.headers.get('content-type') ?? '';
    // A CWT is kept as bytes; anything else (a JWT, or an error body) as text.
    const body = format === 'cwt' && contentType.includes('cwt') ? bytes : new TextDecoder().decode(bytes);
    return { at, format, status: response.status, headers: Object.fromEntries([...response.headers.entries()]), body };
  } catch (error) {
    return { at, format, status: 0, headers: {}, body: '', error: (error as Error).message };
  }
}

/** The issuer and the revocation anchors of a credential, from its signer chain and the suite's trust configuration. */
async function issuerOf(harness: IssuerHarness, credential: IssuedCredential): Promise<MatchedIssuer | undefined> {
  if (!harness.trustStore) return undefined;
  const match = await harness.trustStore.match(harness.trustRule, signerChainOfIssued(credential.format, credential.credential), new Date());
  return match.ok ? { name: match.entity.name, statusAnchors: harness.trustRule.statusAnchors(match.entity, match.service) } : undefined;
}

/** `issuer-event`: the adapter's `setStatus` for every credential an earlier issuance step received. */
export async function runIssuerEvent(
  action: IssuerEventAction,
  stepIndex: number,
  state: LifecycleState,
  ctx: LifecycleContext & {
    adapter: {
      setStatus?: (sessionId: string, status: 'revoked' | 'suspended' | 'valid') => Promise<{ at: string }>;
      changeSubject?: (from: TestSubject, to: TestSubject) => Promise<void>;
      changeDisclosurePolicy?: (sessionId: string) => Promise<{ at: string }>;
    };
  },
): Promise<Evaluation & { event?: { sessionId: string; at: string; status: string } }> {
  // Issue 27 (AP_WS_SM_Revocation_102): the Provider changes the embedded disclosure policy (EDP_11).
  if (action.event === 'change-disclosure-policy') {
    if (!ctx.adapter.changeDisclosurePolicy) return { verdict: 'NOT APPLICABLE', reason: 'the adapter offers no changeDisclosurePolicy (ICS-19, P-EDP)' };
    const issued = state.issued.get(action.ofStep);
    if (!issued?.credentials.length) return { verdict: 'INCONCLUSIVE', reason: `step ${action.ofStep} issued no credential` };
    const { at } = await ctx.adapter.changeDisclosurePolicy(issued.sessionId);
    state.events.set(stepIndex, { at: new Date(at), status: 'disclosure policy changed' });
    return { verdict: 'PASS', reason: `the adapter reports the embedded disclosure policy changed at ${at}`, event: { sessionId: issued.sessionId, at, status: 'disclosure policy changed' } };
  }
  // Issue 26 (PP_WS_SM_Revocation_008): the adapter replaces the subject's data; the event's time counts as `OBS-ADM`.
  if (action.event === 'change-subject') {
    if (!ctx.adapter.changeSubject) return { verdict: 'NOT APPLICABLE', reason: 'the adapter offers no changeSubject (ICS-06.change_subject)' };
    await ctx.adapter.changeSubject(action.from, action.to);
    const at = new Date();
    state.events.set(stepIndex, { at, status: `${action.from} changed to ${action.to}` });
    state.subjects?.set(action.from, action.to);
    return { verdict: 'PASS', reason: `the adapter reports the data of ${action.from} replaced by that of ${action.to} at ${at.toISOString()}`, event: { sessionId: '', at: at.toISOString(), status: `changed to ${action.to}` } };
  }
  if (!ctx.adapter.setStatus) return { verdict: 'INCONCLUSIVE', reason: 'the adapter has no setStatus hook (P-HOOK)' };
  const issued = state.issued.get(action.ofStep);
  if (!issued?.credentials.length) return { verdict: 'INCONCLUSIVE', reason: `step ${action.ofStep} issued no credential to set the status of` };
  const { at } = await ctx.adapter.setStatus(issued.sessionId, action.status);
  state.events.set(stepIndex, { at: new Date(at), status: action.status });
  return { verdict: 'PASS', reason: `the adapter reports the credential(s) of step ${action.ofStep} ${action.status} at ${at}`, event: { sessionId: issued.sessionId, at, status: action.status } };
}

/**
 * `observe-status` (`OBS-SL`): polls the status list of every credential of the steps it names, anonymously, with the
 * `Accept` of the credential's format, every `min(t / 20, 30 s)` until the window ends, keeping every version with its
 * `iat`, `exp`, `ttl` and the credential's status. A window that follows an `issuer-event` counts from the event. The
 * first poll also fetches the list once per format the Provider declares, for `sl-media-type`.
 */
export async function observeStatus(action: ObserveStatusAction, stepIndex: number, state: LifecycleState, ctx: LifecycleContext): Promise<StatusObservation> {
  const window = windowMs(action.t, ctx.ics);
  const eventStep = [...state.events.keys()].filter((s) => s < stepIndex).at(-1);
  const event = eventStep !== undefined ? state.events.get(eventStep) : undefined;
  const credentials: (ObservedCredential & { credential: IssuedCredential; fetched: FetchedVersion[]; perFormat: FetchedVersion[] })[] = [];
  for (const step of action.ofSteps) {
    for (const credential of state.issued.get(step)?.credentials ?? []) {
      let reference: StatusReference | undefined;
      try {
        reference = statusReferenceOfIssued(credential.format, credential.credential);
      } catch {
        reference = undefined;
      }
      credentials.push({ step, configuration: credential.credentialConfigurationId, format: credential.format, ...(reference ? { reference } : {}), polls: [], checks: [], credential, fetched: [], perFormat: [] });
    }
  }
  const from = event?.at ?? new Date();
  const formats = declaredFormats(ctx.ics);
  const poll = async (first: boolean) => {
    const byUri = new Map<string, FetchedVersion>();
    for (const observed of credentials) {
      if (!observed.reference) continue;
      const format = formatOfCredential(observed.format);
      const key = `${format} ${observed.reference.uri}`;
      let fetched = byUri.get(key);
      if (!fetched) {
        fetched = await fetchVersion(ctx.harness, observed.reference.uri, format);
        byUri.set(key, fetched);
      }
      observed.fetched.push(fetched);
      const version = readPublishedVersion(fetched, observed.reference.idx, MAX_STATUS_LIST_BYTES);
      observed.polls.push({
        at: fetched.at.toISOString(),
        uri: observed.reference.uri,
        idx: observed.reference.idx,
        ...(fetched.status ? { status: fetched.status } : {}),
        ...version,
        ...(first ? { headers: fetched.headers } : {}),
      });
      if (first) for (const other of formats) observed.perFormat.push(other === format ? fetched : await fetchVersion(ctx.harness, observed.reference.uri, other));
    }
  };
  await poll(true);
  let until: number;
  let intervalMs: number;
  if (window === 'exp') {
    const exps = credentials.map((c) => c.polls[0]?.exp).filter((e): e is number => typeof e === 'number');
    const firstExp = exps.length ? Math.max(...exps) * 1000 : Date.now();
    intervalMs = pollIntervalMs(Math.max(firstExp - Date.now(), 0));
    until = firstExp + 2 * intervalMs;
  } else {
    intervalMs = pollIntervalMs(window);
    until = from.getTime() + window;
  }
  if (until - Date.now() > 0) ctx.log?.(`    observing ${credentials.length} credential(s) until ${new Date(until).toISOString()}, every ${intervalMs / 1000} s`);
  while (Date.now() < until) {
    await sleep(Math.min(intervalMs, Math.max(until - Date.now(), 0)));
    await poll(false);
  }
  const references = credentials.flatMap((c) => (c.reference ? [c.reference] : []));
  for (const observed of credentials) {
    if (!observed.reference) continue;
    observed.checks = await evaluatePublishedStatus({
      format: formatOfCredential(observed.format),
      reference: observed.reference,
      references,
      issuer: await issuerOf(ctx.harness, observed.credential),
      polls: observed.fetched,
      perFormat: observed.perFormat,
      declaredFormats: formats,
      minEntries: Math.max(Number(issuerIcsValue(ctx.ics, 'ICS-16.min_entries') ?? 0) || 0, 10_000),
      allowLoopbackHttp: true,
      skewSeconds: SKEW_SECONDS,
      maxStatusListBytes: MAX_STATUS_LIST_BYTES,
    });
  }
  return {
    window: { from: from.toISOString(), until: new Date(until).toISOString(), intervalMs, t: action.t },
    ...(event && eventStep !== undefined ? { event: { step: eventStep, at: event.at.toISOString(), status: event.status } } : {}),
    credentials: credentials.map(({ credential: _c, fetched: _f, perFormat: _p, ...rest }) => rest),
  };
}

const label = (c: ObservedCredential, many: boolean) => (many ? `step ${c.step} ${c.configuration}: ` : '');

/** `CONF` over the published list: every check the expectation names passed for every credential observed. */
export function evaluatePublication(observation: StatusObservation, named: string[]): Evaluation {
  if (!observation.credentials.length) return { verdict: 'INCONCLUSIVE', reason: 'no credential was observed' };
  const many = observation.credentials.length > 1;
  const problems: string[] = [];
  const open: string[] = [];
  for (const credential of observation.credentials) {
    if (!credential.reference) {
      problems.push(`${label(credential, many)}the credential has no status reference`);
      continue;
    }
    for (const id of named) {
      const result = credential.checks.find((c) => c.check === id);
      if (!result) open.push(`${label(credential, many)}${id} did not run`);
      else if (result.status === 'fail') problems.push(`${label(credential, many)}${id} failed (${result.detail ?? 'no detail'})`);
      else if (result.status === 'skip') {
        // A skip because a prerequisite failed is a failure of that prerequisite; a skip that does not apply leaves it open.
        if (result.detail?.startsWith('requires ')) problems.push(`${label(credential, many)}${id} could not run: ${result.detail}`);
        else open.push(`${label(credential, many)}${id} not evaluated: ${result.detail}`);
      }
    }
  }
  if (problems.length) return { verdict: 'FAIL', reason: problems.join('; ') };
  if (open.length) return { verdict: 'INCONCLUSIVE', reason: open.join('; ') };
  const details = observation.credentials[0]?.checks.filter((c) => named.includes(c.check)).map((c) => `${c.check}${c.detail ? ` (${c.detail})` : ''}`);
  return { verdict: 'PASS', reason: `${named.join(', ')} passed${many ? ` for ${observation.credentials.length} credentials` : ''}: ${details?.join('; ')}` };
}

/**
 * `REVOKED(t)`: within `t` after the event, the list shows the credential revoked (`0x01`), and every later version
 * does too. A poll without an answer after the first revoked version leaves the verdict open; a poll before it counts
 * for nothing.
 */
export function evaluateRevoked(observation: StatusObservation, windowMsValue: number): Evaluation {
  return evaluateReached(observation, windowMsValue, INVALID, 'revoked');
}

/** Status value of a suspended entry (Token Status List section 7.1: `0x02` SUSPENDED). */
const SUSPENDED = 2;

/**
 * Issue 26: within `windowMs` after the event the list shows the entry with `value`, and every later version does too.
 * `REVOKED(t)` is this for `0x01`; `sl-suspended` and `sl-reinstated` (`PP_WS_SM_Revocation_005`) for `0x02` and `0x00`.
 */
export function evaluateReached(observation: StatusObservation, windowMsValue: number, value: number, name: string): Evaluation {
  const INVALID = value;
  if (!observation.event) return { verdict: 'INCONCLUSIVE', reason: 'no issuer-event before the observation to count t from' };
  if (!observation.credentials.length) return { verdict: 'INCONCLUSIVE', reason: 'no credential was observed' };
  const deadline = Date.parse(observation.event.at) + windowMsValue;
  const many = observation.credentials.length > 1;
  const problems: string[] = [];
  const passes: string[] = [];
  for (const credential of observation.credentials) {
    const first = credential.polls.findIndex((p) => p.value === INVALID);
    if (first < 0) {
      const last = credential.polls.at(-1);
      problems.push(`${label(credential, many)}never shown ${name} in ${credential.polls.length} poll(s) (last: ${last?.value !== undefined ? `0x0${last.value}` : last?.error})`);
      continue;
    }
    const seen = credential.polls[first] as PolledStatus;
    if (Date.parse(seen.at) > deadline) {
      problems.push(`${label(credential, many)}first shown ${name} at ${seen.at}, after the deadline ${new Date(deadline).toISOString()}`);
      continue;
    }
    const reverted = credential.polls.slice(first + 1).find((p) => p.value !== undefined && p.value !== INVALID);
    if (reverted) {
      problems.push(`${label(credential, many)}shown ${name} at ${seen.at}, then 0x0${reverted.value} at ${reverted.at}`);
      continue;
    }
    const versions = new Set(credential.polls.slice(first).map((p) => p.iat)).size;
    passes.push(`${label(credential, many)}${name} at ${seen.at} (${((Date.parse(seen.at) - Date.parse(observation.event.at)) / 1000).toFixed(1)} s after the event), and in all ${credential.polls.length - first} later poll(s), ${versions} version(s)`);
  }
  if (problems.length) return { verdict: 'FAIL', reason: problems.join('; ') };
  return { verdict: 'PASS', reason: passes.join('; ') };
}

/** `UNCHANGED`: the credential is valid (`0x00`) in every version polled. */
export function evaluateUnchanged(observation: StatusObservation): Evaluation {
  if (!observation.credentials.length) return { verdict: 'INCONCLUSIVE', reason: 'no credential was observed' };
  const many = observation.credentials.length > 1;
  const problems: string[] = [];
  for (const credential of observation.credentials) {
    const answered = credential.polls.filter((p) => p.value !== undefined);
    const changed = answered.find((p) => p.value !== VALID);
    if (changed) problems.push(`${label(credential, many)}status 0x0${changed.value} at ${changed.at}`);
    else if (!answered.length) problems.push(`${label(credential, many)}no poll could be read (${credential.polls[0]?.error})`);
  }
  if (problems.length) return { verdict: 'FAIL', reason: problems.join('; ') };
  const polls = observation.credentials.reduce((n, c) => n + c.polls.length, 0);
  return { verdict: 'PASS', reason: `valid in every one of ${polls} poll(s)` };
}

/** Evaluates the codes of an `observe-status` step; the step's verdict is the worst of them. */
export function evaluateObservation(expectation: IssuerExpectation, observation: StatusObservation, ics: LifecycleContext['ics']): Evaluation {
  const evaluations = expectation.codes.map((code: IssuerExpectationCode): Evaluation => {
    if (code === 'CONF') {
      // Issue 26: `sl-suspended` and `sl-reinstated` judge the entry's value within `T_rev` after the event.
      const named = expectation.checks ?? [];
      const values = { 'sl-suspended': [SUSPENDED, 'suspended (0x02)'], 'sl-reinstated': [VALID, 'valid again (0x00)'] } as const;
      const timed = named.filter((c): c is keyof typeof values => c in values);
      const rest = named.filter((c) => !(c in values));
      const results = [
        ...(rest.length ? [evaluatePublication(observation, rest)] : []),
        ...timed.map((c) => {
          const window = windowMs('T_rev', ics);
          return window === 'exp' ? { verdict: 'INCONCLUSIVE' as Verdict, reason: 'T_rev is no duration' } : evaluateReached(observation, window, values[c][0], values[c][1]);
        }),
      ];
      return { verdict: worst(results.map((r) => r.verdict)), reason: results.map((r) => r.reason).join('; ') };
    }
    if (code === 'UNCHANGED') return evaluateUnchanged(observation);
    if (code.startsWith('REVOKED(')) {
      const window = windowMs(code.slice('REVOKED('.length, -1), ics);
      return window === 'exp' ? { verdict: 'INCONCLUSIVE', reason: 'REVOKED needs a duration' } : evaluateRevoked(observation, window);
    }
    if (code === 'INFO') return { verdict: 'PASS', reason: 'recorded' };
    return { verdict: 'INCONCLUSIVE', reason: `expected result ${code} is not implemented for an observe-status step` };
  });
  return { verdict: worst(evaluations.map((e) => e.verdict)), reason: evaluations.map((e) => e.reason).join('; ') };
}

/** What a `present` step saw: the reference Relying Party's result for the presentation of the credential. */
export interface PresentationObservation {
  status: 'success' | 'failure' | 'pending' | 'not-sent';
  error?: string;
  /** The failed checks of the reference validator, with their details. */
  failed: CheckResult[];
  result?: ReferenceRpResult;
  walletError?: string;
}

/**
 * `present`: the reference Relying Party, configured with the suite's trust configuration (`TL-PID` with the Provider as
 * enrolled), asks for `default_query_pid`; the Conformance Wallet answers with the credential of the earlier step, bound
 * to the key of its proof, over redirects (`direct_post.jwt`). The relying party is started for the step and stopped
 * after it.
 */
export async function present(action: PresentAction, state: LifecycleState, ctx: LifecycleContext): Promise<PresentationObservation> {
  const credential = state.issued.get(action.ofStep)?.credentials[0];
  if (!credential) return { status: 'not-sent', error: `step ${action.ofStep} issued no credential`, failed: [] };
  if (credential.format !== 'dc+sd-jwt') return { status: 'not-sent', error: `presenting ${credential.format} is not implemented`, failed: [] };
  const { harness } = ctx;
  if (!harness.env) throw new Error('the Provider is not enrolled');
  const pki = harness.pki;
  const access = pki.relyingPartyAccess;
  const queries = defaultQueries(pki);
  // Issue 27: an Attestation Provider's `default_credential_A`, asked for with the query of its category.
  const query = ({ PID: 'default_query_pid', Q: 'default_query_qeaa', PB: 'default_query_pubeaa', E: 'default_query_eaa' } as const)[harness.category];
  // The harness reaches its own services on the loopback interface, whatever name the Provider uses for them.
  const local = (url: string) => url.replace(`://${ctx.harnessHost}:`, '://127.0.0.1:');
  const lotl = harness.relyingPartyTrust?.listOfTrustedLists;
  const rp = await new ReferenceRelyingParty({
    port: 0,
    host: '127.0.0.1',
    trustLists: harness.env.trustLists.map((list) => ({ ...list, url: local(list.url) })),
    ...(lotl ? { listOfTrustedLists: { ...lotl, url: local(lotl.url), pointers: lotl.pointers.map((p) => ({ ...p, url: local(p.url) })) } } : {}),
    ...(harness.relyingPartyTrust?.rulebooks ? { rulebooks: harness.relyingPartyTrust.rulebooks } : {}),
    accessCertificate: {
      certificatePem: access.certificate.pem,
      certificate: Buffer.from(access.certificate.der).toString('base64'),
      chainPem: access.chain.map((c) => c.pem),
      privateJwk: access.key.privateJwk,
      privateKeyPem: access.key.privateKeyPem,
    },
    registrationCertificate: await issueRegistrationCertificate(pki, [queries[query]]),
    queries,
    skewSeconds: SKEW_SECONDS,
    kbMaxAgeSeconds: 300,
    maxStatusListBytes: MAX_STATUS_LIST_BYTES,
    allowInsecureUrls: true,
  }).start();
  try {
    const refused = (await rp.refreshTrust()).filter((list) => list.error);
    if (refused.length) throw new Error(`the reference Relying Party could not load ${refused.map((l) => `${l.id}: ${l.error}`).join('; ')}`);
    const started = await fetch(`${rp.url}/api/presentations`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ query, flow: 'redirect' }),
    });
    if (started.status !== 201) throw new Error(`the reference Relying Party did not start a presentation: HTTP ${started.status} ${await started.text()}`);
    const { transactionId, uri } = (await started.json()) as { transactionId: string; uri: string };
    const wallet = await ConformanceWallet.create({
      accessCertificateAnchors: [pki.entities['AC-A'].anchors.issuance.certificate],
      allowInsecureUrls: true,
      followRedirect: false,
      holderKey: credential.proofKey,
    });
    const evidence = await wallet.present(uri, { format: 'dc+sd-jwt', value: credential.credential }, { skewSeconds: SKEW_SECONDS });
    let result: ReferenceRpResult | undefined;
    const deadline = Date.now() + 10_000;
    do {
      result = (await (await fetch(`${rp.url}/api/presentations/${transactionId}`)).json()) as ReferenceRpResult;
      if (result.status !== 'pending') break;
      await sleep(200);
    } while (Date.now() < deadline);
    const failed = [...(result?.response ?? []), ...(result?.validations ?? []).flatMap((v) => v.checks)].filter((c) => c.status === 'fail');
    return {
      status: result?.status ?? 'pending',
      ...(result?.error ? { error: result.error } : {}),
      failed,
      ...(result ? { result } : {}),
      ...(evidence.error ? { walletError: evidence.error } : {}),
    };
  } finally {
    await rp.stop();
  }
}

/**
 * `ACC`: the reference Relying Party accepts the presentation. `REJ` in a `present` step: it rejects it, and the check
 * that failed is `status`, the credential's revocation as the Provider published it; a rejection for any other reason
 * says nothing about the Provider's revocation.
 */
export function evaluatePresentation(expectation: IssuerExpectation, observation: PresentationObservation): Evaluation {
  const failures = observation.failed.map((c) => `${c.check} failed (${c.detail ?? 'no detail'})`).join('; ');
  const evaluations = expectation.codes.map((code): Evaluation => {
    if (observation.status === 'not-sent') return { verdict: 'INCONCLUSIVE', reason: observation.error ?? 'nothing was presented' };
    if (observation.status === 'pending') return { verdict: 'INCONCLUSIVE', reason: `the reference Relying Party gave no result${observation.walletError ? ` (wallet: ${observation.walletError})` : ''}` };
    if (code === 'ACC') {
      return observation.status === 'success'
        ? { verdict: 'PASS', reason: `the reference Relying Party accepted the presentation; released ${Object.keys(observation.result?.attributes ?? {}).join(', ')}` }
        : { verdict: 'FAIL', reason: `the reference Relying Party rejected the presentation: ${failures || observation.error || 'no failed check'}` };
    }
    if (code === 'REJ') {
      if (observation.status === 'success') return { verdict: 'FAIL', reason: 'the reference Relying Party accepted the presentation of the revoked credential' };
      const status = observation.failed.find((c) => c.check === 'status');
      if (!status) return { verdict: 'FAIL', reason: `rejected, but not for its status: ${failures || observation.error || 'no failed check'}` };
      const others = observation.failed.filter((c) => c.check !== 'status');
      return others.length
        ? { verdict: 'FAIL', reason: `rejected for its status and for ${others.map((c) => c.check).join(', ')}: ${failures}` }
        : { verdict: 'PASS', reason: `the reference Relying Party rejected the presentation: status failed (${status.detail})` };
    }
    return { verdict: 'INCONCLUSIVE', reason: `expected result ${code} is not implemented for a present step` };
  });
  return { verdict: worst(evaluations.map((e) => e.verdict) as Verdict[]), reason: evaluations.map((e) => e.reason).join('; ') };
}

/** A test case with a step that waits (a window of more than a few seconds): the runner schedules it after the others. */
export function waits(steps: { run?: { kind: string; t?: string } }[]): boolean {
  return steps.some((step) => step.run?.kind === 'observe-status' && step.run.t !== 'PT0S');
}
