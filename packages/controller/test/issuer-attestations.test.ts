// Issuer harness design section 7, level 2, for PP_WS_SM_ClientAttestation, _KeyAttestation and _ProofOfPossession
// (issue 19): every step of every executable definition of these areas, built as the runner builds it
// (`prepareIssuance`, `applyWalletEvent`), is sent to a capture endpoint that judges nothing, and the reference
// validator decides. A step that expects `ISS`, `CONF` or `INFO` (and a fault whose target is no check) passes every
// issuer request check; a step that expects `REJ` fails exactly one: its fault's target, or, after a `wallet-event`,
// the status check of the attestation whose list the event changed.
import { randomUUID } from 'node:crypto';
import { type IssuerFaultId, type IssuerRequestCheck, type IssuerTestCaseDefinition, issuerFaultInfo, type RunningServer, sendJson, startServer, variantOf } from '@eudi-pcaf/core';
import { createTestPki, decodeJws, LIST_PROFILES } from '@eudi-pcaf/forge';
import { issuerDefinitions } from '@eudi-pcaf/issuer-definitions';
import { IssuanceClient, KEY_ATTESTATION_HEADER } from '@eudi-pcaf/issuer-wallet';
import { StatusProvider } from '@eudi-pcaf/status-provider';
import { TrustInfrastructure } from '@eudi-pcaf/trust-infrastructure';
import { checkLote, type LoadedList, validateIssuerRequest } from '@eudi-pcaf/validator';
import { CLIENT_ATTESTATION_HEADER, CLIENT_ATTESTATION_POP_HEADER, publishTlWp, TestWalletProvider, type WalletUnitId } from '@eudi-pcaf/wallet-provider';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { applyWalletEvent, newAttestationState, prepareIssuance, rememberIssuance } from '../src/issuer/attestations';

const CONFIGURATION_ID = 'test_sd_jwt_vc';
const AREAS = /^PP_WS_SM_(ClientAttestation|KeyAttestation|ProofOfPossession)_/;
/** The capture endpoint runs the pre-authorized code flow, as the issuance client does so far. */
const definitions = issuerDefinitions.filter((d) => AREAS.test(d.id) && d.variants?.includes('PA'));

async function startCaptureEndpoint() {
  let base = '';
  const server: RunningServer = await startServer({ host: '127.0.0.1' }, (req, res) => {
    const path = new URL(req.url ?? '/', 'http://localhost').pathname;
    if (path === '/.well-known/openid-credential-issuer') {
      return sendJson(res, 200, {
        credential_issuer: base,
        credential_endpoint: `${base}/credential`,
        nonce_endpoint: `${base}/nonce`,
        credential_configurations_supported: {
          [CONFIGURATION_ID]: {
            format: 'dc+sd-jwt',
            vct: 'urn:test:vct',
            cryptographic_binding_methods_supported: ['jwk'],
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] }, attestation: { proof_signing_alg_values_supported: ['ES256'] } },
          },
        },
      });
    }
    if (path === '/.well-known/oauth-authorization-server') {
      return sendJson(res, 200, {
        issuer: base,
        token_endpoint: `${base}/token`,
        grant_types_supported: ['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
        token_endpoint_auth_methods_supported: ['attest_jwt_client_auth'],
      });
    }
    if (path === '/token') return sendJson(res, 200, { access_token: randomUUID(), token_type: 'DPoP', expires_in: 300 });
    if (path === '/nonce') return sendJson(res, 200, { c_nonce: randomUUID() });
    if (path === '/credential') return sendJson(res, 200, { credentials: [{ credential: 'captured~' }] });
    return sendJson(res, 404, { error: 'not_found' });
  });
  base = server.localUrl;
  const offer = () =>
    `openid-credential-offer://?credential_offer=${encodeURIComponent(
      JSON.stringify({
        credential_issuer: base,
        credential_configuration_ids: [CONFIGURATION_ID],
        grants: { 'urn:ietf:params:oauth:grant-type:pre-authorized_code': { 'pre-authorized_code': randomUUID() } },
      }),
    )}`;
  return { url: base, offer, stop: () => server.close() };
}

const header = (headers: Record<string, string>, name: string) => Object.entries(headers).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1];

let status: StatusProvider;
let trust: TrustInfrastructure;
let twp: TestWalletProvider;
let tlWp: LoadedList;
let capture: Awaited<ReturnType<typeof startCaptureEndpoint>>;

beforeAll(async () => {
  const pki = await createTestPki();
  status = await new StatusProvider().start({ host: '127.0.0.1' });
  trust = await new TrustInfrastructure().start({ host: '127.0.0.1' });
  const { url, jws } = await publishTlWp(trust, 'issuer-attestations', pki);
  const loaded = await checkLote(jws, { id: 'TL-WP', url, loteType: LIST_PROFILES['TL-WP'].loteType, schemeOperatorCertificatePem: pki.schemeOperators['TL-WP'].certificate.pem });
  if (!loaded.list) throw new Error(`TL-WP does not load: ${JSON.stringify(loaded.checks)}`);
  tlWp = loaded.list;
  twp = await TestWalletProvider.create({ pki, statusProvider: status, runId: 'issuer-attestations' });
  capture = await startCaptureEndpoint();
}, 120_000);

afterAll(async () => {
  await capture?.stop();
  await status?.stop();
  await trust?.stop();
});

/** Runs the steps of a definition against the capture endpoint; returns, per issuance step, the failed checks and the expected ones. */
async function selfValidate(definition: IssuerTestCaseDefinition) {
  const state = newAttestationState();
  const usedNonces: string[] = [];
  const usedPopJtis: string[] = [];
  let changedStatus: IssuerRequestCheck | undefined;
  const outcomes: { step: number; failed: string[]; expected: string[]; details: string }[] = [];
  for (const [index, step] of definition.steps.entries()) {
    const run = step.run;
    if (run?.kind === 'wallet-event') {
      await applyWalletEvent(run, { twp, statusProvider: status, namespace: 'issuer-attestations', state, skewSeconds: 300 });
      changedStatus = (run.event === 'revoke-wscd' || run.statusList?.of === 'ka') ? 'ka-status' : 'wia-status';
      continue;
    }
    if (run?.kind !== 'issuance') throw new Error(`${definition.id} step ${index + 1}: ${run?.kind} is not an issuance`);
    const prepared = await prepareIssuance(run, twp, state);
    const client = await IssuanceClient.create(prepared.unit, { allowInsecureUrls: true, hooks: prepared.hooks });
    const evidence = await client.issue({ offer: capture.offer(), signedMetadata: false });
    expect(evidence.error, evidence.error).toBeUndefined();
    const token = evidence.exchanges.filter((e) => e.step === 'token').at(-1)!.request;
    const body = JSON.parse(evidence.exchanges.filter((e) => e.step === 'credential').at(-1)!.request.body ?? '{}') as { proofs: { jwt?: string[]; attestation?: string[] } };
    const proof = body.proofs.jwt?.[0];
    const keyAttestation = body.proofs.attestation?.[0] ?? (proof ? (decodeJws(proof).header[KEY_ATTESTATION_HEADER] as string | undefined) : undefined);
    const clientAttestationPop = header(token.headers, CLIENT_ATTESTATION_POP_HEADER);
    const result = await validateIssuerRequest(
      { clientAttestation: header(token.headers, CLIENT_ATTESTATION_HEADER), clientAttestationPop, clientId: new URLSearchParams(token.body).get('client_id') ?? undefined, proof, keyAttestation },
      {
        walletProviders: tlWp,
        authorizationServer: capture.url,
        credentialIssuer: capture.url,
        cNonce: evidence.cNonce!,
        usedNonces: [...usedNonces],
        usedPopJtis: [...usedPopJtis],
        allowLoopbackHttp: true,
        requireKeyAttestationNonce: Boolean(run.keyAttestationNonce || run.proofType === 'attestation'),
      },
    );
    // The `attestation` proof type has no `jwt` proof: its checks do not apply.
    const failures = result.checks.filter((c) => c.status === 'fail' && !(run.proofType === 'attestation' && c.check.startsWith('proof-')));
    const [fault] = run.faults as IssuerFaultId[];
    const target = fault ? issuerFaultInfo(fault).target : step.expect.codes.some((c) => c.startsWith('REJ')) ? changedStatus : undefined;
    outcomes.push({ step: index + 1, failed: failures.map((c) => c.check), expected: target ? [target] : [], details: failures.map((c) => `${c.check}: ${c.detail}`).join('\n') });
    usedNonces.push(evidence.cNonce!);
    if (clientAttestationPop) usedPopJtis.push(decodeJws(clientAttestationPop).payload.jti as string);
    rememberIssuance(state, (run.walletUnit ?? 'CW-1') as WalletUnitId, evidence);
  }
  return outcomes;
}

describe('issuer definitions of the security mechanisms (level 2)', () => {
  it('covers the 39 test cases of issue 19', () => {
    expect(new Set(issuerDefinitions.filter((d) => AREAS.test(d.id)).map((d) => d.id)).size).toBe(39);
  });

  it.each(definitions.map((d) => [`${d.id} [${variantOf(d)}]`, d] as const))('%s: each step fails exactly the check it targets', async (_, definition) => {
    for (const outcome of await selfValidate(definition)) expect(outcome.failed, `step ${outcome.step}\n${outcome.details}`).toEqual(outcome.expected);
  }, 120_000);
});
