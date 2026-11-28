// Issue 26: the `inspect` step (`CONF` with named checks) over what earlier steps of the test case captured: the
// credentials (`OBS-CRED`) for `PP_WS_SM_IssuerIntegrity` and `PP_WS_SM_Unlinkability`, the signed metadata and the
// status lists for `PP_Inf_SM_TrustMechanisms_007`, and the requests the Provider sent to the harness services
// (`OBS-NET`) for `_008`.
import {
  type CheckResult,
  durationMs,
  type InspectAction,
  ISSUER_INTEGRITY_CHECKS,
  type IssuerExpectation,
  type IssuerIcs,
  type IssuerInspectionCheck,
  UNLINKABILITY_CHECKS,
} from '@eudi-pcaf/core';
import { base64url, decodeJws, parseCertificate, verifyEs256 } from '@eudi-pcaf/forge';
import type { IssuanceEvidence } from '@eudi-pcaf/issuer-wallet';
import {
  checkIssuerIntegrity,
  checkNoWalletIdentifier,
  checkOutboundPrivacy,
  checkUnlinkability,
  type InspectedCredential,
  inspectIssued,
  type OutboundRequest,
  validatePath,
} from '@eudi-pcaf/validator';
import type { Evaluation } from '../evaluate';
import { worst } from '../evaluate';
import { sentAttestations } from './attestations';
import type { IssuerHarness } from './harness';
import { issuerIcsValue } from './ics';

/** What an issuance step left for an `inspect` step. */
export interface CapturedIssuance {
  evidence: IssuanceEvidence;
  /** The reference validator's checks of each credential, in the order of `evidence.credentials`. */
  checks: CheckResult[][];
  receivedAt: Date;
}

export interface InspectState {
  captured?: Map<number, CapturedIssuance>;
  /** When the test case started, for the requests of `OBS-NET`. */
  startedAt?: Date;
}

export interface InspectContext {
  harness: IssuerHarness;
  ics: IssuerIcs;
  harnessHost: string;
}

const der = (certificate: { der: Uint8Array }) => Buffer.from(certificate.der).toString('base64');
const integrity = new Set<string>(ISSUER_INTEGRITY_CHECKS);
const unlinkability = new Set<string>(UNLINKABILITY_CHECKS.filter((c) => c !== 'no-wallet-identifier'));

/** Runs the checks the `CONF` of an `inspect` step names; every check must pass for every credential it applies to. */
export async function runInspection(action: InspectAction, expect: IssuerExpectation, state: InspectState, ctx: InspectContext): Promise<Evaluation & { checks: CheckResult[] }> {
  const named = (expect.checks ?? []) as IssuerInspectionCheck[];
  const captured = action.ofSteps.map((step) => ({ step, capture: state.captured?.get(step) }));
  const missing = captured.filter((c) => !c.capture?.evidence.credentials.length).map((c) => c.step);
  const credentials: { inspected: InspectedCredential; capture: CapturedIssuance; index: number }[] = [];
  for (const { step, capture } of captured) {
    for (const [index, issued] of (capture?.evidence.credentials ?? []).entries()) {
      credentials.push({ inspected: inspectIssued(issued.format, issued.credential, `step ${step} #${index + 1}`, step, capture!.receivedAt), capture: capture!, index });
    }
  }
  const enrolment = ctx.harness.enrolment;
  const results: CheckResult[] = [];
  const label = (c: { inspected: InspectedCredential }, r: CheckResult) => ({ ...r, detail: credentials.length > 1 ? `${c.inspected.label} (${c.inspected.format}): ${r.detail}` : r.detail });

  const perCredential = named.filter((c) => integrity.has(c));
  for (const credential of credentials) {
    const configuration = credential.capture.evidence.metadata?.result.credentialIssuer.credential_configurations_supported[credential.capture.evidence.credentials[credential.index]!.credentialConfigurationId] as
      | { credential_signing_alg_values_supported?: (string | number)[] }
      | undefined;
    const found = checkIssuerIntegrity(credential.inspected, perCredential, {
      ...(enrolment ? { enrolledSigners: enrolment.credentialSigners.map((s) => der(s.certificate)), accessCertificate: der(enrolment.access.certificate) } : {}),
      ...(configuration?.credential_signing_alg_values_supported ? { advertisedAlgorithms: configuration.credential_signing_alg_values_supported } : {}),
    });
    results.push(...found.map((r) => label(credential, r)));
    if (named.includes('no-wallet-identifier')) results.push(label(credential, checkNoWalletIdentifier(credential.inspected, sentAttestations(credential.capture.evidence.exchanges))));
    for (const [check, from] of [
      ['anchor-issuance', 'issuer-trust'],
      ['anchor-revocation', 'status-list-trust'],
    ] as const) {
      if (!named.includes(check)) continue;
      const result = credential.capture.checks[credential.index]?.find((c) => c.check === from);
      results.push(
        label(credential, {
          check,
          status: result?.status ?? 'skip',
          detail: result ? `${from}: ${result.detail ?? result.status}` : `${from} did not run`,
        }),
      );
    }
  }
  const set = named.filter((c) => unlinkability.has(c));
  if (set.length) {
    const precision = durationMs(issuerIcsValue(ctx.ics, 'ICS-16.timestamp_precision'));
    results.push(...checkUnlinkability(credentials.map((c) => c.inspected), set, { precisionSeconds: precision ? precision / 1000 : 1 }));
  }
  if (named.includes('anchor-access')) results.push(await accessAnchor(captured.map((c) => c.capture).filter((c): c is CapturedIssuance => Boolean(c)), ctx));
  if (named.includes('outbound-privacy')) results.push(outbound(state, ctx));

  const problems = results.filter((r) => r.status === 'fail');
  const open = [
    ...missing.map((step) => `step ${step} captured no credential`),
    ...named.filter((check) => !results.some((r) => r.check === check)).map((check) => `${check} did not run`),
    ...results.filter((r) => r.status === 'skip' && !/^applies to/.test(r.detail?.replace(/^step \d+ #\d+ \([^)]*\): /, '') ?? '')).map((r) => `${r.check} not evaluated: ${r.detail}`),
  ];
  if (problems.length) return { verdict: 'FAIL', reason: problems.map((r) => `${r.check} failed: ${r.detail}`).join('; '), checks: results };
  if (open.length) return { verdict: 'INCONCLUSIVE', reason: open.join('; '), checks: results };
  return {
    verdict: worst(['PASS']),
    reason: `${named.join(', ')} passed${credentials.length > 1 ? ` (${credentials.length} credentials)` : ''}: ${results.filter((r) => r.status === 'pass').slice(0, 6).map((r) => `${r.check} (${r.detail})`).join('; ')}`,
    checks: results,
  };
}

/**
 * `anchor-access` (RPACANot_03, PP_Inf_SM_TrustMechanisms_007): the signed Credential Issuer metadata, the artifact the
 * Provider signs with its access certificate, carries the certificate the Test Registrar issued from `AC-A`, its chain
 * validates to the `AC-A` anchor, and its signature verifies.
 */
async function accessAnchor(captures: CapturedIssuance[], ctx: InspectContext): Promise<CheckResult> {
  const check = 'anchor-access' as const;
  const signed = captures.map((c) => c.evidence.metadata?.signed).find((s) => s?.status === 200 && s.body);
  if (!signed?.body) return { check, status: 'fail', detail: 'the Provider served no signed Credential Issuer metadata (Accept application/jwt), the artifact its access certificate signs' };
  const jwt = signed.body.trim();
  let header: Record<string, unknown>;
  try {
    header = decodeJws(jwt).header;
  } catch (error) {
    return { check, status: 'fail', detail: `the signed metadata is no JWS: ${(error as Error).message}` };
  }
  const x5c = Array.isArray(header.x5c) ? (header.x5c as string[]) : [];
  if (!x5c.length) return { check, status: 'fail', detail: 'the signed metadata carries no x5c' };
  const anchor = ctx.harness.pki.entities['AC-A'].anchors.issuance.certificate;
  const path = await validatePath(x5c, [parseCertificate(anchor.pem)]);
  const leaf = parseCertificate(x5c[0] as string);
  const [h, p, s] = jwt.split('.');
  const verified = await verifyEs256(leaf.publicKey.jwk as JsonWebKey, `${h}.${p}`, base64url.decode(s ?? '')).catch(() => false);
  const enrolled = ctx.harness.enrolment?.access.certificate;
  const problems = [
    ...(path.ok ? [] : [`its chain does not validate to AC-A (${path.reason})`]),
    ...(verified ? [] : ['its signature does not verify with the x5c leaf']),
    ...(enrolled && !Buffer.from(enrolled.der).equals(Buffer.from(leaf.der)) ? ['the leaf is not the access certificate the Test Registrar issued'] : []),
  ];
  return problems.length
    ? { check, status: 'fail', detail: `signed metadata: ${problems.join('; ')}` }
    : { check, status: 'pass', detail: `the signed metadata is signed with the enrolled access certificate ${leaf.subject.rfc4514}, chaining to AC-A on TL-AC` };
}

/** `outbound-privacy`: the requests the Provider sent to `TL-WP` and the Test Status Provider since the test case started. */
function outbound(state: InspectState, ctx: InspectContext): CheckResult {
  const since = state.startedAt ?? new Date(0);
  const fromProvider = (entry: { headers: Record<string, string | string[] | undefined> }) => {
    // The harness fetches its own services on the loopback interface; the Provider uses the harness host.
    const host = String(entry.headers.host ?? '');
    return !/^(127\.0\.0\.1|localhost)(:|$)/.test(host) || /^(127\.0\.0\.1|localhost)$/.test(ctx.harnessHost);
  };
  const tlWp = ctx.harness.env?.trustLists.find((l) => l.id === 'TL-WP')?.url;
  const trust = ctx.harness.trust.log.filter((e) => new Date(e.at) >= since && fromProvider(e) && tlWp && e.url.startsWith(tlWp));
  const status = ctx.harness.status.log.filter((e) => new Date(e.at) >= since && fromProvider(e));
  const requests: OutboundRequest[] = [...trust, ...status].map((e) => ({
    at: e.at,
    method: e.method,
    // The Test Status Provider logs the path; the target as received keeps the query.
    url: e.target?.includes('?') ? `${e.url}${e.target.slice(e.target.indexOf('?'))}` : e.url,
    headers: e.headers as Record<string, string | string[] | undefined>,
  }));
  const published = [...(tlWp ? [tlWp] : []), ...status.filter((e) => e.status === 200).map((e) => e.url.replace(/[?#].*$/, ''))];
  return checkOutboundPrivacy(requests, published);
}
