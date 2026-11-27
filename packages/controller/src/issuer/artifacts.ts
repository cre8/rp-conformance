// The steps of the issuer runner over what the Provider publishes and hands out (issue 24, issuer harness design
// sections 2 and 6): the `metadata` action (`SCN-M`, `OBS-META`), the capture of a credential offer for an `issuance`
// step that expects `CONF` (`PP_WS_MS_Offer`), and an issuance with one `credential-request` fault. Each fills the step
// record and evaluates its expectation; the runner calls them from `runIssuerStep` and `runIssuance`.
import { type CheckResult, type CredentialRequestFaultId, type IssuanceAction, type IssuerExpectation, type IssuerIcs, OFFER_CHECKS, type WalletUnit } from '@eudi-pcaf/core';
import {
  type HttpExchange,
  type HttpResponseRecord,
  IssuanceClient,
  type IssuanceEvidence,
  type IssueOptions,
  issueWithCredentialRequestFault,
  nonceRequest,
  send,
  walletUnitOf,
} from '@eudi-pcaf/issuer-wallet';
import { type FetchedArtifact, type ProviderCategory, validateCredentialOffer, validateCredentialRequest, validateIssuerMetadata } from '@eudi-pcaf/validator';
import type { Evaluation } from '../evaluate';
import type { IssuerHarness } from './harness';
import { resolveConfigurations, usesTxCode } from './ics';

/** What these steps need of the runner's context. */
export interface ArtifactStepContext {
  harness: IssuerHarness;
  ics: IssuerIcs;
  adapter: { createOffer: import('@eudi-pcaf/core').IssuerAdapter['createOffer'] };
}

/** What these steps write into the step record (a subset of `IssuerStepRecord`). */
export interface ArtifactStepRecord {
  walletUnit?: string;
  subject?: string;
  offer?: { sessionId: string; offer: string; byReference: boolean; txCode: boolean; configurations: string[] };
  exchanges: HttpExchange[];
  /** The named checks the step ran over the captured artifact. */
  checks?: CheckResult[];
  error?: string;
  verdict: import('@eudi-pcaf/core').Verdict;
  reason: string;
}

/** Offers by value captured earlier in the test case, to compare an offer by reference with (`PP_WS_MS_Offer_002`). */
export interface ArtifactState {
  offersByValue: Record<string, unknown>[];
}

/** `CONF`: every check the expectation names passed on the captured artifact. */
export function evaluateConformance(expectation: IssuerExpectation, checks: CheckResult[]): Evaluation {
  const named = expectation.checks ?? [];
  if (!named.length) return { verdict: 'INCONCLUSIVE', reason: 'the expectation names no checks' };
  const problems = named.flatMap((name) => {
    const result = checks.find((c) => c.check === name);
    if (!result) return [`${name} did not run`];
    if (result.status !== 'pass') return [`${name} ${result.status === 'fail' ? 'failed' : 'was skipped'} (${result.detail ?? 'no detail'})`];
    return [];
  });
  if (problems.length) return { verdict: 'FAIL', reason: problems.join('; ') };
  return { verdict: 'PASS', reason: named.map((name) => `${name}: ${checks.find((c) => c.check === name)?.detail ?? 'passed'}`).join('; ') };
}

/** An issuance step that only captures and checks the offer: it expects `CONF` with offer checks only. */
export const isOfferCapture = (expectation: IssuerExpectation) =>
  expectation.codes.length === 1 && expectation.codes[0] === 'CONF' && (expectation.checks ?? []).every((c) => (OFFER_CHECKS as readonly string[]).includes(c));

const categoryOf = (ics: IssuerIcs): ProviderCategory =>
  ics.profiles.includes('P-Q') ? 'qeaa' : ics.profiles.includes('P-PB') ? 'pub-eaa' : ics.profiles.includes('P-E') ? 'eaa' : 'pid';

const artifactOf = (url: string, response: HttpResponseRecord | undefined): FetchedArtifact | undefined =>
  response
    ? {
        url,
        status: response.status,
        ...(response.headers['content-type'] ? { contentType: response.headers['content-type'] } : {}),
        ...(response.headers['cache-control'] ? { cacheControl: response.headers['cache-control'] } : {}),
        body: response.body,
      }
    : undefined;

const anchorsOf = (harness: IssuerHarness, list: string) =>
  Object.values(harness.pki.entities)
    .filter((e) => e.spec.list === list)
    .map((e) => e.anchors.issuance.certificate);

async function clientFor(ctx: ArtifactStepContext, unit: WalletUnit = 'CW-1') {
  return IssuanceClient.create(walletUnitOf(ctx.harness.twp, unit), { allowInsecureUrls: true });
}

/**
 * `SCN-M`: the Credential Issuer identifier from an offer the adapter creates (as a wallet learns it), the Credential
 * Issuer metadata as JSON and signed, the Authorization Server metadata, two nonce requests, and the probe for a
 * server retrieval endpoint; then every metadata check, and `CONF` over the checks the expectation names.
 */
export async function runMetadata(expectation: IssuerExpectation, record: ArtifactStepRecord, save: (name: string, content: string) => Promise<void>, ctx: ArtifactStepContext) {
  const format = ctx.ics.profiles.includes('P-SD') ? 'SD' : 'MD';
  const grant = ctx.ics.profiles.includes('P-PA') ? 'pre-authorized_code' : 'authorization_code';
  const configurations = resolveConfigurations([`ICS-02.${format}`], ctx.ics);
  const created = await ctx.adapter.createOffer({ subject: 'SUBJ-1', configurations, grant, byReference: false, txCode: usesTxCode(ctx.ics) });
  record.offer = { sessionId: created.sessionId, offer: created.offer, byReference: false, txCode: created.txCode !== undefined, configurations };
  const client = await clientFor(ctx);
  const evidence: IssuanceEvidence = { walletUnit: 'CW-1', exchanges: [], credentials: [] };
  record.exchanges = evidence.exchanges;
  const offer = await client.resolveOffer(created.offer, evidence);
  const credentialIssuer = offer.offer.credential_issuer;
  const metadata = await client.fetchMetadata(credentialIssuer, evidence, { signed: true });
  const unsignedExchange = evidence.exchanges.find((e) => e.step === 'metadata' && e.request.url.includes('/.well-known/openid-credential-issuer'));
  const signedExchange = evidence.exchanges.find((e) => e.step === 'metadata-jwt');

  const nonces: FetchedArtifact[] = [];
  const nonceEndpoint = metadata.result.credentialIssuer.nonce_endpoint;
  if (nonceEndpoint) {
    for (let i = 0; i < 2; i++) {
      const response = await send('nonce', nonceRequest(nonceEndpoint), evidence.exchanges).catch(() => undefined);
      const fetched = artifactOf(nonceEndpoint, response);
      if (fetched) nonces.push(fetched);
    }
  }
  const issuerUrl = new URL(credentialIssuer);
  const probeUrl = `${issuerUrl.origin}/.well-known/openid-configuration${issuerUrl.pathname === '/' ? '' : issuerUrl.pathname.replace(/\/$/, '')}`;
  const probe = await send('metadata', { method: 'GET', url: probeUrl, headers: { accept: 'application/json' } }, evidence.exchanges).catch(() => undefined);

  const validation = await validateIssuerMetadata(
    {
      credentialIssuer,
      ...(unsignedExchange ? { unsigned: artifactOf(unsignedExchange.request.url, unsignedExchange.response) } : {}),
      ...(signedExchange ? { signed: artifactOf(signedExchange.request.url, signedExchange.response) } : {}),
      authorizationServers: metadata.result.authorizationServers as unknown as Record<string, unknown>[],
      nonces,
      ...(probe ? { serverRetrievalProbe: artifactOf(probeUrl, probe) as FetchedArtifact } : {}),
    },
    {
      accessCertificateAnchors: anchorsOf(ctx.harness, 'TL-AC'),
      registrationCertificateAnchors: anchorsOf(ctx.harness, 'TL-RC'),
      category: categoryOf(ctx.ics),
      preAuthorized: ctx.ics.profiles.includes('P-PA'),
      // The harness runs on one machine with the Provider; an http URL on a loopback host stands for https.
      allowLoopbackHttp: true,
    },
  );
  record.checks = validation.checks;
  await save('metadata.json', `${JSON.stringify({ credentialIssuer, metadata: metadata.result, exchanges: evidence.exchanges }, null, 2)}\n`);
  await save('metadata-checks.json', `${JSON.stringify(validation, null, 2)}\n`);
  const evaluation = evaluateConformance(expectation, validation.checks);
  record.verdict = evaluation.verdict;
  record.reason = evaluation.reason;
}

/**
 * `PP_WS_MS_Offer`: the adapter creates the offer of the step, the Conformance Wallet resolves it (fetching
 * `credential_offer_uri` for an offer by reference) and fetches the metadata, without redeeming the offer; then the
 * offer checks and `CONF` over the checks the expectation names.
 */
export async function runOfferCapture(
  expectation: IssuerExpectation,
  action: IssuanceAction,
  record: ArtifactStepRecord,
  save: (name: string, content: string) => Promise<void>,
  ctx: ArtifactStepContext,
  state: ArtifactState,
) {
  const subject = action.subject ?? 'SUBJ-1';
  record.walletUnit = action.walletUnit ?? 'CW-1';
  record.subject = subject;
  const configurations = resolveConfigurations(action.configurations, ctx.ics);
  const byReference = action.offerByReference ?? false;
  const txCode = action.grant === 'pre-authorized_code' && usesTxCode(ctx.ics);
  const created = await ctx.adapter.createOffer({ subject, configurations, grant: action.grant, byReference, txCode });
  record.offer = { sessionId: created.sessionId, offer: created.offer, byReference, txCode: created.txCode !== undefined, configurations };
  const client = await clientFor(ctx, action.walletUnit);
  const evidence: IssuanceEvidence = { walletUnit: record.walletUnit, exchanges: [], credentials: [] };
  record.exchanges = evidence.exchanges;
  const resolved = await client.resolveOffer(created.offer, evidence);
  const metadata = await client.fetchMetadata(resolved.offer.credential_issuer, evidence, { signed: false }).catch((error: Error) => {
    record.error = `metadata: ${error.message}`;
    return undefined;
  });
  const referenceExchange = byReference ? evidence.exchanges.find((e) => e.step === 'offer') : undefined;
  const offer = resolved.offer as unknown as Record<string, unknown>;
  const validation = await validateCredentialOffer({
    offer,
    byReference: resolved.byReference,
    ...(referenceExchange ? { reference: artifactOf(referenceExchange.request.url, referenceExchange.response) as FetchedArtifact } : {}),
    ...(metadata ? { metadata: metadata.result.credentialIssuer as unknown as Record<string, unknown> } : {}),
    ...(state.offersByValue.length ? { byValue: state.offersByValue.at(-1) as Record<string, unknown> } : {}),
    txCodeExpected: created.txCode !== undefined,
    allowLoopbackHttp: true,
  });
  if (!resolved.byReference) state.offersByValue.push(offer);
  record.checks = validation.checks;
  await save('offer.json', `${JSON.stringify({ offer: record.offer, offerObject: resolved, exchanges: evidence.exchanges }, null, 2)}\n`);
  await save('offer-checks.json', `${JSON.stringify(validation, null, 2)}\n`);
  const evaluation = evaluateConformance(expectation, validation.checks);
  record.verdict = evaluation.verdict;
  record.reason = evaluation.reason;
}

/**
 * `SCN-I` with one `credential-request` fault (`PP_WS_MS_CredentialEndpoint`): returns the evidence for the runner's
 * evaluation, or why the fault could not be applied. The faulty request is checked by the reference validator first,
 * so the record shows it fails exactly the fault's target check.
 */
export async function issueWithFault(
  fault: CredentialRequestFaultId,
  offer: { offer: string; txCode?: string },
  configurationId: string,
  unit: WalletUnit,
  ctx: ArtifactStepContext,
  /** The grant and, for the authorization code flow, the adapter's `authenticateSubject` (issue 20). */
  grant: Partial<Pick<IssueOptions, 'grant' | 'authenticate'>> & { foreignIdentifier?: string } = {},
): Promise<{ evidence: IssuanceEvidence; notApplicable?: string; requestChecks?: CheckResult[] }> {
  const result = await issueWithCredentialRequestFault(
    walletUnitOf(ctx.harness.twp, unit),
    { offer: offer.offer, ...(offer.txCode !== undefined ? { txCode: offer.txCode } : {}), credentialConfigurationId: configurationId, fault, ...grant },
    { allowInsecureUrls: true },
  );
  const sent = result.evidence.exchanges.find((e) => e.step === 'credential');
  if (!sent?.request.body || !result.context) return result;
  const validation = await validateCredentialRequest(JSON.parse(sent.request.body), {
    configurationIds: result.context.configurationIds,
    authorizedConfigurationIds: result.context.authorizedConfigurationIds,
    credentialIdentifiers: result.context.credentialIdentifiers,
  });
  return { ...result, requestChecks: validation.checks };
}
