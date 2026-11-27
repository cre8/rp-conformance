// Integration test of the EUDIPLO issuer adapter against a running EUDIPLO (not part of `pnpm test`):
//
//   EUDIPLO_PORT=3216 docker compose --env-file adapters/issuer-eudiplo/reference.env -p eudi-pcaf-i16 \
//     -f adapters/eudiplo/docker-compose.yml up -d --wait
//   EUDIPLO_PORT=3216 pnpm test:issuer-eudiplo
//   docker compose -p eudi-pcaf-i16 -f adapters/eudiplo/docker-compose.yml down -v
//
// It enrols the SUT with the Test Registrar, publishes TL-WP and TL-PID, runs setUp, checks the Credential Issuer
// metadata (plain and signed), creates offers each way, tries setStatus on a session without a credential, and tears
// the tenant down. EUDIPLO_EXPECT_VERSION (default: the pinned reference image, reference.env) is the version the test
// expects the instance to report; the reference's own features (CSR, strict status checks, revocation chaining) are
// checked only when it reports the reference version.
import { buildSealedLote, createTestPki, enrolSut, toEnrolledCertificate, type TestPki } from '@eudi-pcaf/forge';
import { TrustInfrastructure } from '@eudi-pcaf/trust-infrastructure';
import { publishTlWp, WALLET_PROVIDER_IDS } from '@eudi-pcaf/wallet-provider';
import { AuthorizationEndpointError, type IssuerTestEnvironment, type PublishedTrustList } from '@eudi-pcaf/core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { EudiploError, IssuerEudiploAdapter, loadIssuerIcs, PID_DOCTYPE, PID_MDOC_CONFIGURATION, PID_SD_JWT_CONFIGURATION, PID_SUBJECTS, PID_VCT, REFERENCE_EUDIPLO, SECOND_SD_JWT_CONFIGURATION } from '../src/index';

const harnessHost = process.env.HARNESS_HOST ?? 'host.docker.internal';
const namespace = `i16-${Date.now().toString(36)}`;
const expectedVersion = process.env.EUDIPLO_EXPECT_VERSION ?? REFERENCE_EUDIPLO.version;
const isReference = expectedVersion === REFERENCE_EUDIPLO.version;

const decodeJwtPart = (jwt: string, part: 0 | 1) => JSON.parse(Buffer.from(jwt.split('.')[part], 'base64url').toString('utf8'));

/** Resolves an offer URI to the credential offer object, by value or by reference. */
async function resolveOffer(uri: string): Promise<Record<string, any>> {
  const params = new URLSearchParams(uri.slice(uri.indexOf('?') + 1));
  const value = params.get('credential_offer');
  if (value) return JSON.parse(value);
  const reference = params.get('credential_offer_uri');
  if (!reference) throw new Error(`neither credential_offer nor credential_offer_uri in ${uri}`);
  const response = await fetch(reference);
  expect(response.status).toBe(200);
  return response.json();
}

describe('EUDIPLO issuer adapter', () => {
  const adapter = new IssuerEudiploAdapter();
  const trust = new TrustInfrastructure();
  let pki: TestPki;
  let env: IssuerTestEnvironment;

  beforeAll(async () => {
    pki = await createTestPki();
    const csrs = await adapter.enrol(namespace);
    const enrolment = await enrolSut(pki, {
      entity: 'PP-T',
      csrs,
      // With CSRs the adapter names the format of each key; 9.1.0 imports a generated SD-JWT VC signer and document signer.
      credentialSigningProfiles: csrs?.credentialSigningProfiles ?? ['sd-jwt-vc', 'mdoc'],
      statusListWithIssuanceKey: false,
      access: { entityIdentifier: 'VATDE-987654321', serviceIdentifier: 'S1', tradeName: 'PID Provider under test' },
      registration: {
        providesAttestations: [
          { format: 'dc+sd-jwt', meta: { vct_values: [PID_VCT] } },
          { format: 'mso_mdoc', meta: { doctype_value: PID_DOCTYPE } },
        ],
      },
    });
    await trust.start({ port: 0, publicHost: harnessHost });
    const lists: PublishedTrustList[] = [];
    const loteTypeOf = (document: unknown, id: string) =>
      (document as { LoTE?: { ListAndSchemeInformation?: { LoTEType?: string } } }).LoTE?.ListAndSchemeInformation?.LoTEType ?? id;
    // TL-WP as the Test Wallet Provider publishes it: WP-A (separate WIA and KA anchors), WP-B, WP-W.
    const tlWp = await publishTlWp(trust, namespace, pki);
    lists.push({ id: 'TL-WP', loteType: loteTypeOf(tlWp.document, 'TL-WP'), url: tlWp.url, schemeOperatorCertificatePem: pki.schemeOperators['TL-WP'].certificate.pem });
    const tlPid = await buildSealedLote({ list: 'TL-PID', pki, distributionPoint: trust.urlOf(namespace, 'TL-PID') });
    const { url: tlPidUrl } = trust.publish(namespace, 'TL-PID', tlPid.jws);
    lists.push({ id: 'TL-PID', loteType: loteTypeOf(tlPid.document, 'TL-PID'), url: tlPidUrl, schemeOperatorCertificatePem: pki.schemeOperators['TL-PID'].certificate.pem });
    env = {
      runId: namespace,
      trustLists: lists,
      credentialSigningCertificates: enrolment.credentialSigners.map(toEnrolledCertificate),
      credentialSigningProfiles: enrolment.credentialSigners.map((signer) => signer.profile),
      statusListSigningCertificate: enrolment.statusListSigner && toEnrolledCertificate(enrolment.statusListSigner),
      accessCertificate: toEnrolledCertificate(enrolment.access),
      registrationCertificate: enrolment.registrationCertificate,
      ics: await loadIssuerIcs(),
    };
    await adapter.setUp(env, namespace);
  }, 120_000);

  afterAll(async () => {
    await adapter.tearDown().catch(() => undefined);
    await trust.stop();
  });

  it('enrols as the instance allows and reports its version', async () => {
    const described = await adapter.describe();
    expect(described.version).toBe(expectedVersion);
    expect(described.tenant).toBe(adapter.tenant);
    console.info('describe():', described);
  });

  it.runIf(isReference)('enrols the reference by CSR, with strict status checks and revocation chaining', async () => {
    const described = await adapter.describe();
    expect(described.revision).toBe(REFERENCE_EUDIPLO.revision);
    expect(described.enrolment).toMatch(/^CSR/);
    expect(described.walletAttestationStatusCheckMode).toBe('strict');
    expect(described.revokeWithWalletUnit).toBe('on');
    const { issuance, pid } = await adapter.configuration();
    expect(issuance.walletAttestationStatusCheckMode).toBe('strict');
    expect(issuance.walletAttestationRequired).toBe(true);
    expect(pid.revokeWithWalletUnit).toBe(true);
    expect(pid.statusManagement).toBe(true);
  });

  it('serves the Credential Issuer metadata of the tenant with the PID configuration', async () => {
    const response = await fetch(`${adapter.baseUrl}/.well-known/openid-credential-issuer/issuers/${adapter.tenant}`);
    expect(response.status).toBe(200);
    const metadata = await response.json();
    expect(metadata.credential_issuer).toBe(adapter.credentialIssuer);
    const mdoc = metadata.credential_configurations_supported?.[PID_MDOC_CONFIGURATION];
    expect(mdoc?.format).toBe('mso_mdoc');
    expect(mdoc?.doctype).toBe(PID_DOCTYPE);
    const pid = metadata.credential_configurations_supported?.[PID_SD_JWT_CONFIGURATION];
    expect(pid).toBeDefined();
    expect(pid.format).toBe('dc+sd-jwt');
    expect(pid.vct).toBe(PID_VCT);
    expect(pid.cryptographic_binding_methods_supported).toContain('jwk');
    for (const proofType of Object.values(pid.proof_types_supported ?? {}) as { key_attestations_required?: unknown }[]) {
      expect(proofType.key_attestations_required).toEqual({ key_storage: ['iso_18045_high'], user_authentication: ['iso_18045_high'] });
    }
    // ICS-11, ICS-12, ICS-13 as declared.
    expect(metadata.nonce_endpoint).toBeDefined();
    expect(metadata.notification_endpoint).toBeDefined();
    expect(metadata.batch_credential_issuance?.batch_size).toBe(env.ics.items['ICS-08.batch_size']);
    expect(metadata.credential_request_encryption?.encryption_required).toBe(false);
    expect(metadata.credential_response_encryption?.encryption_required).toBe(false);
    console.info('credential issuer metadata:', JSON.stringify(metadata));
  });

  it('requires wallet attestation at its authorization server', async () => {
    const response = await fetch(`${adapter.baseUrl}/.well-known/oauth-authorization-server/issuers/${adapter.tenant}`);
    expect(response.status).toBe(200);
    const metadata = await response.json();
    expect(metadata.token_endpoint_auth_methods_supported).toContain('attest_jwt_client_auth');
    expect(metadata.dpop_signing_alg_values_supported).toContain('ES256');
    console.info('authorization server metadata:', JSON.stringify(metadata));
  });

  it('signs the metadata with the access certificate the Registrar issued', async () => {
    const response = await fetch(`${adapter.baseUrl}/.well-known/openid-credential-issuer/issuers/${adapter.tenant}`, {
      headers: { accept: 'application/jwt' },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('application/jwt');
    const jwt = await response.text();
    const header = decodeJwtPart(jwt, 0);
    expect(header.typ).toBe('openidvci-issuer-metadata+jwt');
    expect(header.x5c).toEqual(env.accessCertificate.chainPem.map((pem) => pem.replace(/-----(BEGIN|END) CERTIFICATE-----|\s+/g, '')));
    const payload = decodeJwtPart(jwt, 1);
    expect(payload.iss).toBe(adapter.credentialIssuer);
    expect(payload.credential_configurations_supported?.[PID_SD_JWT_CONFIGURATION]).toBeDefined();
  });

  it('creates an offer by value without tx_code', async () => {
    const created = await adapter.createOffer({ subject: 'SUBJ-1', configurations: [PID_SD_JWT_CONFIGURATION], grant: 'pre-authorized_code', byReference: false });
    expect(created.offer).toMatch(/^openid-credential-offer:\/\/\?credential_offer=/);
    expect(created.txCode).toBeUndefined();
    const offer = await resolveOffer(created.offer);
    expect(offer.credential_issuer).toBe(adapter.credentialIssuer);
    expect(offer.credential_configuration_ids).toEqual([PID_SD_JWT_CONFIGURATION]);
    const grant = offer.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code'];
    expect(grant?.['pre-authorized_code']).toEqual(expect.any(String));
    expect(grant?.tx_code).toBeUndefined();
  });

  it('creates an offer by reference with tx_code', async () => {
    const created = await adapter.createOffer({
      subject: 'SUBJ-2',
      configurations: [PID_SD_JWT_CONFIGURATION],
      grant: 'pre-authorized_code',
      byReference: true,
      txCode: true,
    });
    expect(created.offer).toMatch(/^openid-credential-offer:\/\/\?credential_offer_uri=/);
    expect(created.txCode).toMatch(/^\d{6}$/);
    const offer = await resolveOffer(created.offer);
    const grant = offer.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code'];
    expect(grant?.tx_code).toMatchObject({ length: 6, input_mode: 'numeric' });
    // Resolvable once: a second fetch answers 404 (ISSUER_MULTI_CONSUMPTION is not set).
    const reference = new URLSearchParams(created.offer.slice(created.offer.indexOf('?') + 1)).get('credential_offer_uri') as string;
    expect((await fetch(reference)).status).toBe(404);
  });

  it('seeds the subject with the offer', async () => {
    const created = await adapter.createOffer({ subject: 'SUBJ-1', configurations: [PID_SD_JWT_CONFIGURATION], grant: 'pre-authorized_code', byReference: true });
    expect(PID_SUBJECTS['SUBJ-1'].family_name).not.toBe(PID_SUBJECTS['SUBJ-2'].family_name);
    expect(created.sessionId).toEqual(expect.any(String));
  });

  it('cannot change the status of a session that has issued no credential yet', async () => {
    const created = await adapter.createOffer({ subject: 'SUBJ-1', configurations: [PID_SD_JWT_CONFIGURATION], grant: 'pre-authorized_code', byReference: true });
    expect(await adapter.credentialStatus(created.sessionId)).toEqual([]);
    const error = await adapter.setStatus(created.sessionId, 'revoked').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(EudiploError);
    expect((error as EudiploError).status).toBe(409);
    console.info('setStatus without an issued credential:', (error as EudiploError).message);
  });

  // Issue 20: authorization code offers, the second configuration, and authenticateSubject at the built-in server.
  it('creates authorization code offers with issuer_state, and offers for the second configuration (ICS-02.second)', async () => {
    const created = await adapter.createOffer({ subject: 'SUBJ-1', configurations: [PID_SD_JWT_CONFIGURATION], grant: 'authorization_code', byReference: false });
    const offer = await resolveOffer(created.offer);
    expect(offer.grants?.authorization_code?.issuer_state).toEqual(expect.any(String));
    expect(offer.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']).toBeUndefined();
    expect(created.txCode).toBeUndefined();
    const second = await resolveOffer((await adapter.createOffer({ subject: 'SUBJ-1', configurations: [SECOND_SD_JWT_CONFIGURATION], grant: 'pre-authorized_code', byReference: false, txCode: true })).offer);
    expect(second.credential_configuration_ids).toEqual([SECOND_SD_JWT_CONFIGURATION]);
    const metadata = await (await fetch(`${adapter.baseUrl}/.well-known/openid-credential-issuer/issuers/${adapter.tenant}`)).json();
    expect(metadata.credential_configurations_supported?.[SECOND_SD_JWT_CONFIGURATION]).toMatchObject({ format: 'dc+sd-jwt', vct: PID_VCT });
  });

  it('answers an authorization request without a pushed request_uri with an error page, which authenticateSubject throws', async () => {
    const as = await (await fetch(`${adapter.baseUrl}/.well-known/oauth-authorization-server/issuers/${adapter.tenant}`)).json();
    expect(as.pushed_authorization_request_endpoint).toEqual(expect.any(String));
    const error = await adapter.authenticateSubject(`${as.authorization_endpoint}?response_type=code&client_id=c&redirect_uri=https%3A%2F%2Fw.invalid%2Fcb`, 'SUBJ-1').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AuthorizationEndpointError);
    expect((error as AuthorizationEndpointError).status).toBe(409);
  });

  it('keeps status lists of 2 bits, 10 000 entries and the shortest lifetime, re-signed on every change', async () => {
    expect(await adapter.statusListSettings()).toMatchObject({ bits: 2, capacity: 10_000, ttl: 60, immediateUpdate: true });
  });

  it('is given the TL-WP of the Test Wallet Provider', async () => {
    const tlWp = env.trustLists.find((list) => list.id === 'TL-WP');
    const response = await fetch((tlWp?.url ?? '').replace(harnessHost, '127.0.0.1'));
    expect(response.status).toBe(200);
    const payload = decodeJwtPart(await response.text(), 1);
    const names = (payload.LoTE?.TrustedEntitiesList ?? []).flatMap((e: { TrustedEntityInformation: { TEName: { value: string }[] } }) =>
      e.TrustedEntityInformation.TEName.map((n) => n.value),
    );
    for (const id of WALLET_PROVIDER_IDS.filter((id) => id !== 'WP-C')) expect(names.join(' ')).toContain(id);
  });

  it('refreshes its trust list cache', async () => {
    await expect(adapter.refreshTrust()).resolves.toBeUndefined();
  });

  it('removes the tenant on tearDown', async () => {
    const tenant = adapter.tenant;
    const baseUrl = adapter.baseUrl;
    await adapter.tearDown();
    const response = await fetch(`${baseUrl}/.well-known/openid-credential-issuer/issuers/${tenant}`);
    expect(response.status).not.toBe(200);
  });
});
