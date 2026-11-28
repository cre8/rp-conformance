// The metadata and offer checks of the issuer suite (issue 24, `OBS-META`): metadata as the Test Registrar enrols a
// Provider passes every check, and each faulty artifact fails exactly its check and no other (issuer harness design
// section 7, level 1). The signed metadata is signed with the enrolled access certificate's key.
import { createTestPki, enrolSut, type Enrolment, PID_DOCTYPE, PID_VCT, type TestPki } from '@eudi-pcaf/forge';
import { CompactSign, importJWK } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { type FetchedArtifact, type MetadataObservation, validateCredentialOffer, validateIssuerMetadata, wellKnownMetadataUrl } from '../src/index';

const ISSUER = 'https://pp-t.rp-test/issuers/t1';
type Json = Record<string, unknown>;

const keyAttestations = { key_storage: ['iso_18045_high'], user_authentication: ['iso_18045_high'] };
const proofTypes = { jwt: { proof_signing_alg_values_supported: ['ES256'], key_attestations_required: keyAttestations } };
const reusePolicy = { id: 'arf_annex_ii', options: [{ details: ['once_only'], batch_size: 2, reissue_trigger_unused: 1 }, { details: ['limited_time'], reissue_trigger_lifetime_left: 86400 }] };

function validMetadata(registrationCertificate: string): Json {
  return {
    credential_issuer: ISSUER,
    authorization_servers: [ISSUER],
    credential_endpoint: `${ISSUER}/credential`,
    nonce_endpoint: `${ISSUER}/nonce`,
    batch_credential_issuance: { batch_size: 2 },
    display: [{ name: 'PID Provider under test', locale: 'en-US' }],
    issuer_info: [{ format: 'registration_cert', data: registrationCertificate }],
    credential_configurations_supported: {
      'pid-sd-jwt-vc': {
        format: 'dc+sd-jwt',
        vct: PID_VCT,
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: ['ES256'],
        proof_types_supported: proofTypes,
        credential_metadata: { credential_reuse_policy: reusePolicy },
      },
      'pid-mso-mdoc': {
        format: 'mso_mdoc',
        doctype: PID_DOCTYPE,
        cryptographic_binding_methods_supported: ['cose_key'],
        credential_signing_alg_values_supported: [-7],
        proof_types_supported: proofTypes,
        credential_reuse_policy: reusePolicy,
      },
    },
  };
}

const validAuthorizationServer = (): Json => ({
  issuer: ISSUER,
  token_endpoint: `${ISSUER}/token`,
  pushed_authorization_request_endpoint: `${ISSUER}/par`,
  require_pushed_authorization_requests: true,
  code_challenge_methods_supported: ['S256'],
  dpop_signing_alg_values_supported: ['ES256'],
  token_endpoint_auth_methods_supported: ['attest_jwt_client_auth'],
  grant_types_supported: ['authorization_code', 'urn:ietf:params:oauth:grant-type:pre-authorized_code'],
});

const nonce = (cNonce: string, cacheControl = 'no-store'): FetchedArtifact => ({
  url: `${ISSUER}/nonce`,
  status: 200,
  contentType: 'application/json',
  cacheControl,
  body: JSON.stringify({ c_nonce: cNonce }),
});

let pki: TestPki;
let enrolment: Enrolment;

beforeAll(async () => {
  pki = await createTestPki();
  enrolment = await enrolSut(pki, {
    entity: 'PP-T',
    access: { entityIdentifier: 'VATDE-987654321', serviceIdentifier: 'S1', tradeName: 'PID Provider under test' },
    registration: {
      providesAttestations: [
        { format: 'dc+sd-jwt', meta: { vct_values: [PID_VCT] } },
        { format: 'mso_mdoc', meta: { doctype_value: PID_DOCTYPE } },
      ],
    },
  });
});

interface Variation {
  metadata?: (m: Json) => void;
  signedPayload?: (p: Json) => void;
  header?: (h: Json) => void;
  authorizationServer?: (as: Json) => void;
  observation?: (o: MetadataObservation) => void;
}

async function observe(variation: Variation = {}): Promise<MetadataObservation> {
  const metadata = validMetadata(enrolment.registrationCertificate);
  variation.metadata?.(metadata);
  const payload: Json = { ...structuredClone(metadata), sub: ISSUER, iat: Math.floor(Date.now() / 1000) };
  variation.signedPayload?.(payload);
  const header: Json = {
    alg: 'ES256',
    typ: 'openidvci-issuer-metadata+jwt',
    x5c: enrolment.access.chain.map((c) => Buffer.from(c.der).toString('base64')),
  };
  variation.header?.(header);
  const key = await importJWK(enrolment.access.key?.privateJwk as never, 'ES256');
  const jws = await new CompactSign(new TextEncoder().encode(JSON.stringify(payload))).setProtectedHeader(header as never).sign(key);
  const as = validAuthorizationServer();
  variation.authorizationServer?.(as);
  const observation: MetadataObservation = {
    credentialIssuer: ISSUER,
    unsigned: { url: wellKnownMetadataUrl(ISSUER), status: 200, contentType: 'application/json', body: JSON.stringify(metadata) },
    signed: { url: wellKnownMetadataUrl(ISSUER), status: 200, contentType: 'application/jwt', body: jws },
    authorizationServers: [as],
    nonces: [nonce('n-1'), nonce('n-2')],
  };
  variation.observation?.(observation);
  return observation;
}

const options = () => ({
  accessCertificateAnchors: [pki.entities['AC-A'].anchors.issuance.certificate],
  registrationCertificateAnchors: [pki.entities['RC-A'].anchors.issuance.certificate],
  category: 'pid' as const,
  preAuthorized: true,
});

const sdJwtConfiguration = (m: Json) => (m.credential_configurations_supported as Record<string, Json>)['pid-sd-jwt-vc'] as Json;

describe('issuer metadata checks', () => {
  it('accepts the metadata of an enrolled Provider: every check passes', async () => {
    const result = await validateIssuerMetadata(await observe(), options());
    // Issue 27: the checks of configurations that are not device-bound and of embedded disclosure policies do not
    // apply to a Provider without either.
    expect(result.checks.filter((c) => c.status !== 'pass').map((c) => `${c.check} ${c.status}`)).toEqual(['metadata-no-key-binding skip', 'metadata-disclosure-policy skip']);
    expect(result.checks).toHaveLength(17);
  });

  const faults: [string, Variation][] = [
    ['metadata-location', { observation: (o) => Object.assign(o.unsigned as FetchedArtifact, { contentType: 'text/html' }) }],
    ['metadata-location', { observation: (o) => Object.assign(o, { credentialIssuer: `${ISSUER}/other` }), signedPayload: (p) => Object.assign(p, { sub: `${ISSUER}/other` }) }],
    ['metadata-signed', { header: (h) => Object.assign(h, { typ: 'JWT' }) }],
    ['metadata-signed', { header: (h) => Object.assign(h, { x5c: [...(h.x5c as string[]), Buffer.from(pki.entities['AC-A'].anchors.issuance.certificate.der).toString('base64')] }) }],
    ['metadata-signed', { signedPayload: (p) => Object.assign(p, { sub: 'https://other.example' }) }],
    ['metadata-signed-equal', { signedPayload: (p) => Object.assign(p, { batch_credential_issuance: { batch_size: 3 } }) }],
    ['metadata-registration-certificate', { metadata: (m) => Object.assign(m, { issuer_info: [] }) }],
    [
      'metadata-registration-entitlement',
      {
        metadata: (m) =>
          Object.assign(m.credential_configurations_supported as Json, { other: { ...sdJwtConfiguration(m), vct: 'urn:example:other:1' } }),
      },
    ],
    ['metadata-pid-configurations', { metadata: (m) => delete (m.credential_configurations_supported as Json)['pid-mso-mdoc'] }],
    ['metadata-algorithms', { metadata: (m) => Object.assign(sdJwtConfiguration(m), { credential_signing_alg_values_supported: ['ES256K'] }) }],
    ['metadata-algorithms', { authorizationServer: (as) => Object.assign(as, { dpop_signing_alg_values_supported: ['ES256', 'HS256'] }) }],
    [
      'metadata-key-attestation',
      {
        metadata: (m) =>
          Object.assign(sdJwtConfiguration(m), {
            proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'], key_attestations_required: { ...keyAttestations, key_storage: ['iso_18045_moderate', 'iso_18045_high'] } } },
          }),
      },
    ],
    ['metadata-key-attestation', { metadata: (m) => Object.assign(sdJwtConfiguration(m), { proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } } }) }],
    ['metadata-reuse-policy', { metadata: (m) => Object.assign(sdJwtConfiguration(m), { credential_metadata: {} }) }],
    ['metadata-reuse-policy', { metadata: (m) => Object.assign(m, { batch_credential_issuance: { batch_size: 1 } }) }],
    ['metadata-nonce-endpoint', { observation: (o) => Object.assign(o, { nonces: [nonce('same'), nonce('same')] }) }],
    ['metadata-nonce-endpoint', { observation: (o) => Object.assign(o, { nonces: [nonce('n-1'), nonce('n-2', 'max-age=60')] }) }],
    ['metadata-authorization-server', { authorizationServer: (as) => Object.assign(as, { code_challenge_methods_supported: ['plain', 'S256'] }) }],
    ['metadata-authorization-server', { authorizationServer: (as) => Object.assign(as, { require_pushed_authorization_requests: false }) }],
    ['metadata-authorization-server', { authorizationServer: (as) => Object.assign(as, { token_endpoint_auth_methods_supported: ['none'] }) }],
    ['metadata-authorization-server', { authorizationServer: (as) => Object.assign(as, { 'pre-authorized_grant_anonymous_access_supported': true }) }],
    ['metadata-display', { metadata: (m) => Object.assign(m, { display: [{ name: 'Another Provider', locale: 'en-US' }] }) }],
    ['metadata-no-server-retrieval', { authorizationServer: (as) => Object.assign(as, { userinfo_endpoint: `${ISSUER}/userinfo` }) }],
  ];

  it.each(faults)('fails exactly %s', async (check, variation) => {
    const result = await validateIssuerMetadata(await observe(variation), options());
    expect(result.failures).toEqual([check]);
  });

  it('skips the PID configuration check for an Attestation Provider', async () => {
    const result = await validateIssuerMetadata(await observe(), { ...options(), category: 'eaa' });
    expect(result.checks.find((c) => c.check === 'metadata-pid-configurations')?.status).toBe('skip');
  });
});

describe('credential offer checks', () => {
  const metadata = { credential_issuer: ISSUER, credential_configurations_supported: { 'pid-sd-jwt-vc': {} } };
  const offerOf = (code = '0fcb335e-9f77-40d9-99c9-273dfa934fa2', tx: unknown = { input_mode: 'numeric', length: 6, description: 'Code' }) => ({
    credential_issuer: ISSUER,
    credential_configuration_ids: ['pid-sd-jwt-vc'],
    grants: { 'urn:ietf:params:oauth:grant-type:pre-authorized_code': { 'pre-authorized_code': code, ...(tx ? { tx_code: tx } : {}) } },
  });
  const reference = (contentType = 'application/json'): FetchedArtifact => ({ url: `${ISSUER}/offers/1`, status: 200, contentType, body: '{}' });
  const byReference = (offer: Json, byValue: Json, contentType?: string) => ({ offer, byReference: true, reference: reference(contentType), metadata, byValue, txCodeExpected: true });

  it('accepts a valid offer by value and by reference', async () => {
    const byValue = await validateCredentialOffer({ offer: offerOf(), byReference: false, metadata, txCodeExpected: true });
    expect(byValue.failures).toEqual([]);
    const ref = await validateCredentialOffer(byReference(offerOf('another-code'), offerOf()));
    expect(ref.failures).toEqual([]);
    expect(ref.checks.filter((c) => c.status === 'pass').map((c) => c.check)).toEqual(['offer-issuer', 'offer-configurations', 'offer-reference-fetch', 'offer-reference-equal', 'offer-pre-authorized-code']);
  });

  const header = Buffer.from(JSON.stringify({ alg: 'ES256' })).toString('base64url');
  const cases: [string, Parameters<typeof validateCredentialOffer>[0]][] = [
    ['offer-issuer', { offer: { ...offerOf(), credential_issuer: 'http://pp-t.rp-test/issuers/t1' }, byReference: false, metadata, txCodeExpected: true }],
    ['offer-configurations', { offer: { ...offerOf(), credential_configuration_ids: ['unknown'] }, byReference: false, metadata, txCodeExpected: true }],
    ['offer-reference-fetch', byReference(offerOf(), offerOf(), 'text/plain')],
    ['offer-reference-equal', byReference(offerOf('x', { input_mode: 'numeric', length: 4, description: 'Code' }), offerOf())],
    ['offer-pre-authorized-code', { offer: offerOf(`${header}.e30.c2ln`), byReference: false, metadata, txCodeExpected: true }],
    ['offer-pre-authorized-code', { offer: offerOf(undefined, null), byReference: false, metadata, txCodeExpected: true }],
    ['offer-pre-authorized-code', { offer: offerOf(undefined, { input_mode: 'numeric' }), byReference: false, metadata, txCodeExpected: true }],
    ['offer-issuer-state', { offer: { ...offerOf(), grants: { authorization_code: { issuer_state: '' } } }, byReference: false, metadata }],
  ];

  it.each(cases)('fails exactly %s', async (check, observation) => {
    expect((await validateCredentialOffer(observation)).failures).toEqual([check]);
  });
});

// Issue 27: the checks of an Attestation Provider's configurations (AP_WS_MS_Metadata_100 to _103), on the PID
// Provider's metadata with one configuration added or changed; only the named check is looked at.
describe('Attestation Provider metadata checks', () => {
  // As a QEAA Provider: `metadata-key-attestation` then requires no level, and `metadata-key-attestation-levels` does.
  const statusOf = async (check: string, metadata: (m: Json) => void) =>
    (await validateIssuerMetadata(await observe({ metadata, signedPayload: metadata }), { ...options(), category: 'qeaa' as const })).checks.find((c) => c.check === check);
  const addNdb = (extra: Json = {}) => (m: Json) => {
    const { cryptographic_binding_methods_supported: _b, proof_types_supported: _p, ...rest } = sdJwtConfiguration(m);
    (m.credential_configurations_supported as Record<string, Json>)['ndb'] = { ...rest, ...extra };
  };

  it('metadata-no-key-binding passes for a configuration without binding and proof types, and fails with a proof type', async () => {
    expect((await statusOf('metadata-no-key-binding', addNdb()))?.status).toBe('pass');
    const withProof = await statusOf('metadata-no-key-binding', addNdb({ proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'], key_attestations_required: {} } } }));
    expect(withProof?.status).toBe('fail');
    expect(withProof?.detail).toMatch(/requires a key attestation/);
  });

  it('metadata-key-attestation-levels fails for a device-bound configuration without key_storage', async () => {
    expect((await statusOf('metadata-key-attestation-levels', () => {}))?.status).toBe('pass');
    const result = await statusOf('metadata-key-attestation-levels', (m) => {
      const jwt = ((sdJwtConfiguration(m).proof_types_supported as Json).jwt as Json).key_attestations_required as Json;
      delete jwt.key_storage;
    });
    expect(result?.status).toBe('fail');
  });

  it('metadata-disclosure-policy passes for a policy by value and fails for one only by reference', async () => {
    expect((await statusOf('metadata-disclosure-policy', (m) => Object.assign(sdJwtConfiguration(m), { credential_metadata: { policy: { policy: 'allowList' } } })))?.status).toBe('pass');
    expect((await statusOf('metadata-disclosure-policy', (m) => Object.assign(sdJwtConfiguration(m), { policy_uri: 'https://pp-t.rp-test/policy' })))?.status).toBe('fail');
  });

  it('metadata-attestation-formats fails for a configuration in another format', async () => {
    expect((await statusOf('metadata-attestation-formats', () => {}))?.status).toBe('pass');
    expect((await statusOf('metadata-attestation-formats', (m) => Object.assign(sdJwtConfiguration(m), { format: 'jwt_vc_json' })))?.status).toBe('fail');
  });
});

