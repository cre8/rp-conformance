import { randomInt } from 'node:crypto';
import {
  AuthorizationEndpointError,
  type CreatedOffer,
  type CreateOfferRequest,
  type EnrolledCertificate,
  type EnrolmentRequest,
  type IssuerAdapter,
  type IssuerTestEnvironment,
  type RunningServer,
  sendJson,
  startServer,
  type TestSubject,
} from '@eudi-pcaf/core';
import { icsList, icsNumber } from './ics';
import { ATTESTATION_MDOC_FIELDS, ATTESTATION_SD_JWT_FIELDS, attestationClaimsFor, PID_FIELDS, PID_MDOC_FIELDS, PID_SD_JWT_EXTRA_FIELDS, pidClaimsFor } from './subjects';

export { durationSeconds, ICS_PATH, icsList, icsNumber, icsProblems, loadIssuerIcs } from './ics';
export { REFERENCE_ENV_PATH, REFERENCE_EUDIPLO, type ReferenceEudiplo } from './reference';
export { ATTESTATION_MDOC_FIELDS, ATTESTATION_SD_JWT_FIELDS, attestationClaimsFor, PID_FIELDS, PID_MDOC_FIELDS, PID_SUBJECTS, pidClaimsFor } from './subjects';

/** The ID of the PID credential configuration in SD-JWT VC format, as the Credential Issuer metadata names it. */
export const PID_SD_JWT_CONFIGURATION = 'pid-sd-jwt-vc';
/** A second PID configuration that no offer names (issue 24, PP_WS_MS_CredentialEndpoint_004_UF). */
export const SECOND_SD_JWT_CONFIGURATION = 'pid-sd-jwt-vc-2';
/** `vct` of the PID in SD-JWT VC format (PID Rulebook). */
export const PID_VCT = 'urn:eudi:pid:1';
/** The ID of the PID credential configuration in mdoc format (ICS-02.MD). */
export const PID_MDOC_CONFIGURATION = 'pid-mso-mdoc';
/** DocType of the PID in mdoc format (PID Rulebook). */
export const PID_DOCTYPE = 'eu.europa.ec.eudi.pid.1';
/** The short-lived PID configurations (ICS-05.short.SD, ICS-05.short.MD): no status reference, 12 hours. */
export const PID_SD_JWT_SHORT_CONFIGURATION = 'pid-sd-jwt-vc-short';
export const PID_MDOC_SHORT_CONFIGURATION = 'pid-mso-mdoc-short';
/** The built-in authorization server of the tenant: the only one that redeems pre-authorized codes. */
const BUILT_IN_AS = 'issuer-built-in';

/** Shortest status list token lifetime EUDIPLO accepts (`ttl`, `GET/PUT /api/status-list-config`, minimum 60). */
export const STATUS_LIST_TTL_SECONDS = 60;
/** Lifetime of the PID; more than 24 hours, so it carries a status reference (ICS-05.validity_period). */
const PID_LIFETIME_SECONDS = 30 * 24 * 60 * 60;
/**
 * Access token lifetime of the built-in authorization server: EUDIPLO's minimum (60 s; default 300 s), so
 * `PP_WS_SM_TokenBinding_007_UF` waits for an expired token within the run's wait limit (ICS-14.access_token).
 */
const ACCESS_TOKEN_LIFETIME_SECONDS = 60;
/** `interval` the deferral webhook asks EUDIPLO to hand to the wallet, seconds. */
const DEFERRAL_INTERVAL_SECONDS = 1;
/** Lifetime of the short-lived PID, without status reference (ICS-05.short.validity_period). */
const PID_SHORT_LIFETIME_SECONDS = 12 * 60 * 60;

/**
 * Issue 27: the attestation configurations of an Attestation Provider tenant (QEAA, PuB-EAA, non-qualified EAA), FCAF
 * `default_credential_A`, by the ICS reference that names them; the IDs come from the tenant's ICS (`categories.<c>`).
 */
const ATTESTATION_CONFIGURATIONS: { ref: string; format: 'SD' | 'MD'; lifetime: number; short: boolean; deviceBound: boolean; second?: boolean; edp?: boolean }[] = [
  { ref: 'ICS-02.SD', format: 'SD', lifetime: 30 * 24 * 60 * 60, short: false, deviceBound: true },
  { ref: 'ICS-02.second', format: 'SD', lifetime: 30 * 24 * 60 * 60, short: false, deviceBound: true, second: true },
  { ref: 'ICS-02.MD', format: 'MD', lifetime: 30 * 24 * 60 * 60, short: false, deviceBound: true },
  { ref: 'ICS-05.short.SD', format: 'SD', lifetime: 12 * 60 * 60, short: true, deviceBound: true },
  { ref: 'ICS-05.short.MD', format: 'MD', lifetime: 12 * 60 * 60, short: true, deviceBound: true },
  { ref: 'ICS-04.NDB.SD', format: 'SD', lifetime: 30 * 24 * 60 * 60, short: false, deviceBound: false },
  // Only AP_WS_SM_Revocation_102 issues from it: changing its policy revokes every attestation issued under it (EDP_11).
  { ref: 'ICS-19.EDP.SD', format: 'SD', lifetime: 30 * 24 * 60 * 60, short: false, deviceBound: true, edp: true },
];
/** `vct`, doctype and namespace of `default_credential_A` (the forge's `CREDENTIAL_A_VCT`, `CREDENTIAL_A_DOCTYPE`). */
export const ATTESTATION_VCT = 'urn:rp-conformance:credential_a:1';
export const ATTESTATION_DOCTYPE = 'test.rp-conformance.credential_a.1';
/** The relying party the embedded disclosure policy allows (ICS-19), and the one `changeDisclosurePolicy` allows instead. */
const DISCLOSURE_POLICY_RP = 'https://rp.rp-test';
const CHANGED_DISCLOSURE_POLICY_RP = 'https://rp-b.rp-test';
/** The category names of the tenants, for descriptions and the display name (the trade name of the access certificate). */
const CATEGORY_NAMES = { 'P-Q': 'QEAA Provider', 'P-PB': 'PuB-EAA Provider', 'P-E': 'non-qualified EAA Provider' } as const;

/** The PID configurations the adapter creates: format, lifetime, and whether they carry a status reference. */
const PID_CONFIGURATIONS: Record<string, { format: 'SD' | 'MD'; lifetime: number; short: boolean }> = {
  [PID_SD_JWT_CONFIGURATION]: { format: 'SD', lifetime: PID_LIFETIME_SECONDS, short: false },
  // Offered on its own by PP_WS_IA_PreAuthorized_004_UF (ICS-02.second, issue 20).
  [SECOND_SD_JWT_CONFIGURATION]: { format: 'SD', lifetime: PID_LIFETIME_SECONDS, short: false },
  [PID_MDOC_CONFIGURATION]: { format: 'MD', lifetime: PID_LIFETIME_SECONDS, short: false },
  [PID_SD_JWT_SHORT_CONFIGURATION]: { format: 'SD', lifetime: PID_SHORT_LIFETIME_SECONDS, short: true },
  [PID_MDOC_SHORT_CONFIGURATION]: { format: 'MD', lifetime: PID_SHORT_LIFETIME_SECONDS, short: true },
};

export interface IssuerEudiploAdapterOptions {
  /**
   * Base URL of EUDIPLO as the harness reaches it; default `EUDIPLO_URL`, or `http://127.0.0.1:<EUDIPLO_PORT>` (port 3000
   * by default). Not `localhost`: Docker publishes EUDIPLO on 127.0.0.1 only, and `localhost` may resolve to `::1` first.
   */
  baseUrl?: string;
  /** Root client of EUDIPLO (`AUTH_CLIENT_ID` / `AUTH_CLIENT_SECRET`). */
  clientId?: string;
  clientSecret?: string;
  /** Host under which EUDIPLO reaches the harness services; default `HARNESS_HOST`, or `host.docker.internal` (Compose). */
  harnessHost?: string;
}

/**
 * What the reference image has beyond the release 9.1.0, and the adapter uses where the instance under test accepts it,
 * so the same adapter still configures 9.1.0 (without them).
 */
export interface EudiploCapabilities {
  /** `GET /api/key-chain/{id}/csr` (EUDIPLO/eudiplo#1397): enrolment by CSR instead of key import. */
  csr: boolean;
  /** `walletAttestationStatusCheckMode` (EUDIPLO/eudiplo#1340, #1468): `strict` for WIAs and KAs. */
  statusCheckMode: boolean;
  /** `revokeWithWalletUnit` (EUDIPLO/eudiplo#1468): the PID is revoked with its wallet unit (revocation chaining). */
  revokeWithWalletUnit: boolean;
}

/** One entry of `GET /api/session/{id}/credential-status`. */
export interface CredentialStatusEntry {
  credentialConfigurationId: string;
  statusListId: string;
  index: number;
  status: number;
  bits: number;
}

const STATUS_VALUE = { valid: 0, revoked: 1, suspended: 2 } as const;

/** A failed call to EUDIPLO, with the HTTP status and the body it answered. */
export class EudiploError extends Error {
  constructor(
    readonly method: string,
    readonly path: string,
    readonly status: number,
    readonly body: string,
  ) {
    super(`EUDIPLO ${method} ${path}: HTTP ${status} ${body}`);
  }

  /** EUDIPLO's schema validation rejected a field it does not know (an older release). */
  get unrecognizedKey(): boolean {
    return this.status === 400 && this.body.includes('unrecognized_keys');
  }
}

/** The key chains of the tenant, by usage. */
interface KeyChains {
  attestation: string;
  /** The mdoc document signer, where the ICS declares mdoc (P-MD). */
  mdocAttestation?: string;
  statusList?: string;
  access: string;
}

/** Tenant IDs are lowercase letters, digits, '-' and '_', at most 63 characters. */
const tenantIdOf = (namespace: string) => namespace.toLowerCase().replace(/[^a-z0-9_-]/g, '-').slice(0, 63);

/**
 * Adapter for EUDIPLO as the reference PID Provider (issuer harness design sections 5.4 and 5.5). One tenant per
 * namespace, as the RP adapter does:
 *
 * - `enrol` returns CSRs where the instance offers `GET /api/key-chain/{id}/csr`; EUDIPLO 9.1.0 does not, so it returns
 *   `undefined` and `setUp` imports the keys the Test Registrar generated (`POST /api/key-chain/import`).
 * - `setUp` creates the tenant, its key chains (credential signer, status list signer, access certificate), the status
 *   list settings, the PID configuration in SD-JWT VC and the issuance configuration: wallet attestation required, the
 *   harness's `TL-WP` as the only wallet provider list, key attestations with the ICS levels, DPoP.
 * - `createOffer` seeds the subject with the offer (`credentialClaims` `inline`), pre-authorized code with or without
 *   `tx_code`, or authorization code. EUDIPLO offers by reference only; for an offer by value the adapter resolves the
 *   reference itself.
 * - `authenticateSubject` opens the authorization request at the built-in authorization server, which has no login, and
 *   returns its redirect to the wallet.
 * - `setStatus` calls `POST /api/session/revoke` and confirms with `GET /api/session/{id}/credential-status`.
 * - `refreshTrust` clears EUDIPLO's trust list cache.
 */
export class IssuerEudiploAdapter implements IssuerAdapter {
  readonly name = 'issuer-eudiplo';
  readonly baseUrl: string;
  readonly harnessHost: string;
  private rootToken?: string;
  private token?: string;
  private tenantId?: string;
  private keyChains?: KeyChains;
  private version?: { version?: string; revision?: string };
  private method?: 'csr' | 'generated';
  /** The configurations `setUp` created. */
  private configurations = new Set<string>();
  private capabilities: EudiploCapabilities = { csr: false, statusCheckMode: false, revokeWithWalletUnit: false };
  /** Issue 25: the claims webhook that defers every issuance it is asked for (`P-DEF`), started on first use. */
  private deferralWebhook?: { server: RunningServer; url: string };
  // Issue 26 (changeSubject): the sessions of each subject's offers, and subjects whose data were replaced.
  private sessionsOf = new Map<TestSubject, string[]>();
  private dataOf = new Map<TestSubject, TestSubject>();
  /** Issue 27: the configurations of an Attestation Provider tenant (`default_credential_A`), by ID; empty for a PID Provider. */
  private attestations = new Map<string, { format: 'SD' | 'MD'; lifetime: number }>();
  /** Issue 27: the category of the tenant, from the profiles of its ICS. */
  private category?: keyof typeof CATEGORY_NAMES;

  constructor(private readonly options: IssuerEudiploAdapterOptions = {}) {
    this.baseUrl = (options.baseUrl ?? process.env.EUDIPLO_URL ?? `http://127.0.0.1:${process.env.EUDIPLO_PORT ?? 3000}`).replace(/\/$/, '');
    this.harnessHost = options.harnessHost ?? process.env.HARNESS_HOST ?? 'host.docker.internal';
  }

  /** The tenant's Credential Issuer identifier, `{PUBLIC_URL}/issuers/{tenant}`, as the harness reaches it. */
  get credentialIssuer(): string {
    return `${this.baseUrl}/issuers/${this.requireTenant()}`;
  }

  get tenant(): string | undefined {
    return this.tenantId;
  }

  private requireTenant(): string {
    if (!this.tenantId) throw new Error('the EUDIPLO issuer adapter is not set up');
    return this.tenantId;
  }

  private async call<T>(method: string, path: string, body?: unknown, token = this.token): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: {
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await response.text();
    if (!response.ok) throw new EudiploError(method, path, response.status, text);
    return (text ? JSON.parse(text) : undefined) as T;
  }

  private async getToken(clientId: string, clientSecret: string): Promise<string> {
    const { access_token } = await this.call<{ access_token: string }>(
      'POST',
      '/api/oauth2/token',
      { grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret },
      undefined,
    );
    return access_token;
  }

  /** Logs in as the root client, reads the version and detects the capabilities beyond 9.1.0. */
  private async connect(): Promise<string> {
    if (this.rootToken) return this.rootToken;
    this.rootToken = await this.getToken(
      this.options.clientId ?? process.env.EUDIPLO_CLIENT_ID ?? 'rp-conformance',
      this.options.clientSecret ?? process.env.EUDIPLO_CLIENT_SECRET ?? 'rp-conformance-secret',
    );
    this.version = await this.call<{ version?: string; revision?: string }>('GET', '/api/version', undefined, this.rootToken).catch(() => ({}));
    // A route EUDIPLO lacks answers 404 "Cannot GET ..." before any guard; a route it has answers 401 without a token.
    const probe = await fetch(`${this.baseUrl}/api/key-chain/00000000-0000-0000-0000-000000000000/csr`);
    const probeBody = await probe.text();
    this.capabilities.csr = !(probe.status === 404 && probeBody.includes('Cannot GET'));
    return this.rootToken;
  }

  /** Creates the tenant of the namespace, replacing one left from an earlier run, and logs in as its client. */
  private async createTenant(namespace: string): Promise<void> {
    const rootToken = await this.connect();
    const id = tenantIdOf(namespace);
    const body = {
      id,
      name: `Issuer conformance ${namespace}`,
      description: 'Created by the issuer conformance harness',
      roles: ['issuance:manage', 'issuance:offer'],
    };
    let tenant: { client: { clientId: string; clientSecret: string } };
    try {
      tenant = await this.call('POST', '/api/tenant', body, rootToken);
    } catch (error) {
      if (!(error instanceof EudiploError) || error.status !== 409) throw error;
      await this.call('DELETE', `/api/tenant/${id}`, undefined, rootToken);
      tenant = await this.call('POST', '/api/tenant', body, rootToken);
    }
    this.tenantId = id;
    this.token = await this.getToken(tenant.client.clientId, tenant.client.clientSecret);
  }

  /**
   * CSRs for the credential signer, the status list signer and the access certificate, where EUDIPLO can create them
   * (after 9.1.0): the tenant and three standalone key chains are created here, and `setUp` stores the certificates the
   * Registrar issued. EUDIPLO 9.1.0 has no CSR endpoint: `undefined`, and the Registrar generates the keys.
   */
  async enrol(namespace?: string): Promise<EnrolmentRequest | undefined> {
    await this.connect();
    if (!this.capabilities.csr) {
      this.method = 'generated';
      return undefined;
    }
    if (!namespace) throw new Error('EUDIPLO creates the keys of a CSR in a tenant: enrol needs the namespace setUp will get');
    await this.createTenant(namespace);
    const create = async (usageType: string, description: string) =>
      (await this.call<{ id: string }>('POST', '/api/key-chain', { usageType, type: 'standalone', description })).id;
    const csrOf = async (id: string) => (await this.call<{ csr: string }>('GET', `/api/key-chain/${id}/csr`)).csr;
    this.keyChains = {
      attestation: await create('attestation', 'PID signer (SD-JWT VC), certified by the Test Registrar under PP-T'),
      mdocAttestation: await create('attestation', 'PID document signer (mdoc), certified by the Test Registrar under PP-T'),
      statusList: await create('statusList', 'Status list signer, certified by the Test Registrar under PP-T'),
      access: await create('access', 'Access certificate from AC-A'),
    };
    this.method = 'csr';
    return {
      credentialSigning: [await csrOf(this.keyChains.attestation), await csrOf(this.keyChains.mdocAttestation as string)],
      credentialSigningProfiles: ['sd-jwt-vc', 'mdoc'],
      statusListSigning: await csrOf(this.keyChains.statusList as string),
      access: await csrOf(this.keyChains.access),
    };
  }

  /** Stores a certificate the Registrar issued for a CSR, or imports a key the Registrar generated with its certificate. */
  private async keyChain(usageType: string, certificate: EnrolledCertificate, description: string, csrKeyChain?: string): Promise<string> {
    if (csrKeyChain) {
      await this.call('PUT', `/api/key-chain/${csrKeyChain}`, { activeCertificate: certificate.chainPem.join('\n') });
      return csrKeyChain;
    }
    if (!certificate.privateKeyPem) throw new Error(`the Registrar issued the ${usageType} certificate without its key, but EUDIPLO needs it`);
    const { id } = await this.call<{ id: string }>('POST', '/api/key-chain/import', {
      usageType,
      description,
      keyPem: certificate.privateKeyPem,
      crt: certificate.chainPem,
    });
    return id;
  }

  async setUp(env: IssuerTestEnvironment, namespace: string): Promise<void> {
    if (this.method === 'csr') {
      if (this.tenantId !== tenantIdOf(namespace)) throw new Error(`enrolled in tenant ${this.tenantId}, set up for ${namespace}`);
    } else {
      await this.createTenant(namespace);
      this.method = 'generated';
    }
    const profiles = env.credentialSigningProfiles ?? env.credentialSigningCertificates.map(() => 'sd-jwt-vc' as const);
    const signer = env.credentialSigningCertificates[profiles.indexOf('sd-jwt-vc')];
    const documentSigner = profiles.includes('mdoc') ? env.credentialSigningCertificates[profiles.indexOf('mdoc')] : undefined;
    if (!signer) throw new Error('no credential signing certificate for SD-JWT VC from the Test Registrar');
    const enrolled = this.keyChains;
    const attestation = await this.keyChain('attestation', signer, 'PID signer under PP-T, from the Test Registrar', enrolled?.attestation);
    const mdocAttestation = documentSigner
      ? await this.keyChain('attestation', documentSigner, 'PID document signer under PP-T, from the Test Registrar', enrolled?.mdocAttestation)
      : undefined;
    const statusList = env.statusListSigningCertificate
      ? await this.keyChain('statusList', env.statusListSigningCertificate, 'Status list signer under PP-T, from the Test Registrar', enrolled?.statusList)
      : undefined;
    const access = await this.keyChain('access', env.accessCertificate, 'Access certificate from AC-A, from the Test Registrar', enrolled?.access);
    this.keyChains = { attestation, ...(mdocAttestation ? { mdocAttestation } : {}), statusList, access };

    // Status lists: 2 bits per entry (suspension), at least 10 000 entries (ICS-16, decision 4), the shortest token
    // lifetime EUDIPLO accepts, re-signed on every change. Without a status list key chain EUDIPLO signs with the
    // attestation key, as the ICS then declares.
    await this.call('PUT', '/api/status-list-config', {
      capacity: icsNumber(env.ics, 'ICS-16.min_entries', 10_000),
      bits: 2,
      ttl: STATUS_LIST_TTL_SECONDS,
      immediateUpdate: true,
      enableAggregation: true,
    });

    const keyAttestationsRequired = {
      key_storage: icsList(env.ics, 'ICS-04.key_storage', ['iso_18045_high']),
      user_authentication: icsList(env.ics, 'ICS-04.user_authentication', ['iso_18045_high']),
    };
    this.configurations.clear();
    this.attestations.clear();
    const batchSize = icsNumber(env.ics, 'ICS-08.batch_size', 1);
    // Issue 24 (PP_WS_MS_Metadata_009): the reuse policy of ARF Annex II, method A (once_only) preferred over method B
    // (limited_time), consistent with the batch size (ICS-08.credential_reuse_policy), on every configuration.
    const reuse = batchSize >= 2 ? { credentialReusePolicy: reusePolicy(batchSize) } : {};
    const display = (name: string) => [{ name, locale: 'en-US', description: 'Person identification data of the conformance test subject' }];
    // Revocation chaining (WURevocation_18): EUDIPLO follows the status of the key attestation (the wallet unit
    // attestation) and revokes the PID with it. 9.1.0 does not know the field.
    const sdJwt = async (id: string, short: boolean, description?: string) => {
      const dropped = await this.postWithoutUnknownKeys('/api/issuer/credentials', {
        id,
        description: description ?? `PID in SD-JWT VC format (PID Rulebook), default_configuration_PP_1${short ? ', short-lived without status reference' : ''}`,
        config: { format: 'dc+sd-jwt', display: display(short ? 'PID (short-lived)' : 'PID'), keyAttestationsRequired, ...reuse },
        vct: PID_VCT,
        keyBinding: true,
        statusManagement: !short,
        keyChainId: attestation,
        lifeTime: short ? PID_SHORT_LIFETIME_SECONDS : PID_LIFETIME_SECONDS,
        fields: [...PID_FIELDS, ...PID_SD_JWT_EXTRA_FIELDS],
        ...(short ? {} : { revokeWithWalletUnit: true }),
      });
      this.configurations.add(id);
      return dropped;
    };
    // The PID in mdoc format (ICS-02.MD), signed by the document signer: EUDIPLO signs an mdoc with the key chain of
    // its configuration and puts the claims of a field's namespace in that namespace.
    const mdoc = async (id: string, short: boolean) => {
      await this.postWithoutUnknownKeys('/api/issuer/credentials', {
        id,
        description: `PID in mdoc format (PID Rulebook), default_configuration_PP_1${short ? ', short-lived without status reference' : ''}`,
        config: { format: 'mso_mdoc', docType: PID_DOCTYPE, display: display(short ? 'PID mdoc (short-lived)' : 'PID mdoc'), keyAttestationsRequired, ...reuse },
        keyBinding: true,
        statusManagement: !short,
        keyChainId: mdocAttestation,
        lifeTime: short ? PID_SHORT_LIFETIME_SECONDS : PID_LIFETIME_SECONDS,
        fields: PID_MDOC_FIELDS,
        ...(short ? {} : { revokeWithWalletUnit: true }),
      });
      this.configurations.add(id);
    };
    const short = env.ics.profiles.includes('P-SHORT');
    // Issue 27: a tenant whose ICS names an Attestation Provider category issues `default_credential_A` instead.
    this.category = (Object.keys(CATEGORY_NAMES) as (keyof typeof CATEGORY_NAMES)[]).find((p) => env.ics.profiles.includes(p));
    if (this.category) {
      await this.setUpAttestations(env, { attestation, mdocAttestation, keyAttestationsRequired, reuse, short });
      await this.setUpIssuance(env, batchSize, `EUDIPLO ${CATEGORY_NAMES[this.category]} under conformance test`);
      return;
    }
    const droppedFromPid = await sdJwt(PID_SD_JWT_CONFIGURATION, false);
    this.capabilities.revokeWithWalletUnit = !droppedFromPid.includes('revokeWithWalletUnit');
    // Issue 24 (PP_WS_MS_CredentialEndpoint_004_UF): a second configuration that no PID offer names, so a credential
    // request can name a configuration the access token was not issued for. Issue 20 (PP_WS_IA_PreAuthorized_004_UF,
    // ICS-02.second) offers it on its own, to try that offer's code against the PID configuration.
    await sdJwt(SECOND_SD_JWT_CONFIGURATION, false, 'Second PID configuration in SD-JWT VC format, never offered: target of PP_WS_MS_CredentialEndpoint_004_UF');
    if (short) await sdJwt(PID_SD_JWT_SHORT_CONFIGURATION, true);
    if (env.ics.profiles.includes('P-MD')) {
      if (!mdocAttestation) throw new Error('the ICS declares mdoc (P-MD), but the Test Registrar issued no document signer');
      await mdoc(PID_MDOC_CONFIGURATION, false);
      if (short) await mdoc(PID_MDOC_SHORT_CONFIGURATION, true);
    }

    await this.setUpIssuance(env, batchSize, 'EUDIPLO PID Provider under conformance test');
  }

  /**
   * Issue 27: the configurations of `default_credential_A` for an Attestation Provider tenant: device-bound in SD-JWT VC
   * (`ICS-02.SD`, and the second configuration `ICS-02.second`) and mdoc (`ICS-02.MD`), the short-lived ones
   * (`ICS-05.short.*`), one that is not device-bound (`ICS-04.NDB.SD`, ICS-04 `P-NDB`), and with `P-EDP` the one whose
   * embedded disclosure policy `AP_WS_SM_Revocation_102` changes (`ICS-19.EDP.SD`, ICS-19). Revocation chaining
   * (`revokeWithWalletUnit`) as ICS-07 declares it, the KA levels of ICS-04.
   */
  private async setUpAttestations(
    env: IssuerTestEnvironment,
    o: { attestation: string; mdocAttestation?: string; keyAttestationsRequired: Record<string, string[]>; reuse: Record<string, unknown>; short: boolean },
  ): Promise<void> {
    const name = CATEGORY_NAMES[this.category as keyof typeof CATEGORY_NAMES];
    const chains = env.ics.profiles.includes('P-CHAIN') && /^(yes|true)$/i.test(String(env.ics.items['ICS-07'] ?? ''));
    const ndb = env.ics.profiles.includes('P-NDB');
    for (const c of ATTESTATION_CONFIGURATIONS) {
      if (c.short && !o.short) continue;
      if (!c.deviceBound && !ndb) continue;
      if (c.edp && !env.ics.profiles.includes('P-EDP')) continue;
      if (c.format === 'MD' && !env.ics.profiles.includes('P-MD')) continue;
      const id = env.ics.items[c.ref];
      if (typeof id !== 'string') throw new Error(`the ICS of the ${name} names no configuration under ${c.ref}`);
      const what = `${c.format === 'SD' ? 'SD-JWT VC' : 'mdoc'}${c.short ? ', short-lived without status reference' : ''}${c.deviceBound ? '' : ', not device-bound'}${c.second ? ', second configuration (never offered with the first)' : ''}${c.edp ? ', embedded disclosure policy changed by AP_WS_SM_Revocation_102' : ''}`;
      const display = [{ name: `default_credential_A (${name})`, locale: 'en-US', description: 'FCAF default_credential_A of the conformance test subject' }];
      const proof = c.deviceBound ? { keyAttestationsRequired: o.keyAttestationsRequired } : {};
      // ICS-19 (`P-EDP`): an embedded disclosure policy, published as `disclosure_policy` of the configuration.
      const edp = env.ics.profiles.includes('P-EDP') ? { embeddedDisclosurePolicy: { policy: 'allowList', values: [DISCLOSURE_POLICY_RP] } } : {};
      if (c.format === 'MD' && !o.mdocAttestation) throw new Error('the ICS declares mdoc (P-MD), but the Test Registrar issued no document signer');
      await this.postWithoutUnknownKeys('/api/issuer/credentials', {
        id,
        description: `FCAF default_credential_A as ${name} (${what}), default_configuration_PP_1`,
        config:
          c.format === 'SD'
            ? { format: 'dc+sd-jwt', display, ...proof, ...o.reuse }
            : { format: 'mso_mdoc', docType: ATTESTATION_DOCTYPE, display, ...proof, ...o.reuse },
        ...(c.format === 'SD' ? { vct: ATTESTATION_VCT } : {}),
        keyBinding: c.deviceBound,
        statusManagement: !c.short,
        keyChainId: c.format === 'SD' ? o.attestation : o.mdocAttestation,
        lifeTime: c.lifetime,
        fields: c.format === 'SD' ? ATTESTATION_SD_JWT_FIELDS : ATTESTATION_MDOC_FIELDS,
        ...(c.short || !c.deviceBound ? {} : { revokeWithWalletUnit: chains }),
        ...edp,
      });
      this.configurations.add(id);
      this.attestations.set(id, { format: c.format, lifetime: c.lifetime });
    }
    this.capabilities.revokeWithWalletUnit = chains;
  }

  /** The issuance configuration of the tenant: wallet attestation, `TL-WP`, DPoP, batch, registration certificate. */
  private async setUpIssuance(env: IssuerTestEnvironment, batchSize: number, displayName: string): Promise<void> {
    const tlWp = env.trustLists.find((list) => list.id === 'TL-WP');
    if (!tlWp) throw new Error('TL-WP is not published');
    const walletProviderTrustLists = [{ url: tlWp.url, verifierX509Der: derOf(tlWp.schemeOperatorCertificatePem) }];
    // Issue 27: ICS-18 decides how an Attestation Provider treats an unobtainable WIA or KA status (`reject`: strict).
    const statusCheckMode = /^accept/i.test(String(env.ics.items['ICS-18'] ?? 'reject')) && this.category ? 'best_effort' : 'strict';
    const issuance = {
      display: [{ name: displayName, locale: 'en-US' }],
      authorizationServers: [{ type: 'built-in', id: BUILT_IN_AS, walletAttestationRequired: true, token: { lifetimeSeconds: ACCESS_TOKEN_LIFETIME_SECONDS } }],
      walletAttestationRequired: true,
      walletProviderTrustLists,
      batchSize,
      dPopRequired: true,
      notificationEndpointEnabled: true,
      // 9.1.0 imports the Registrar's certificate with `mode` `import` (its default `generate` asks a registrar);
      // later releases have no `mode` and publish `jwt` as given.
      registrationCertificate: { enabled: true, mode: 'import', jwt: env.registrationCertificate },
      // A PID Provider rejects a WIA or KA whose status it cannot obtain (catalogue decision 2): `strict`, for WIAs at
      // the authorization server (inherited) and KAs at the credential endpoint. 9.1.0 has no such setting and accepts
      // them (best effort).
      walletAttestationStatusCheckMode: statusCheckMode,
    };
    const dropped = await this.postWithoutUnknownKeys('/api/issuer/config', issuance);
    this.capabilities.statusCheckMode = !dropped.includes('walletAttestationStatusCheckMode');
  }

  /**
   * POSTs a configuration that names fields of several EUDIPLO releases: where the instance's schema validation
   * rejects a field it does not know (`unrecognized_keys`), the field is left out and the call repeated. Any other
   * rejection fails. Returns the dotted paths of the fields left out.
   */
  private async postWithoutUnknownKeys(path: string, body: Record<string, unknown>): Promise<string[]> {
    const dropped: string[] = [];
    for (;;) {
      try {
        await this.call('POST', path, body);
        return dropped;
      } catch (error) {
        if (!(error instanceof EudiploError) || !error.unrecognizedKey) throw error;
        const { errors = [] } = JSON.parse(error.body) as { errors?: { path: (string | number)[]; message: string; code: string }[] };
        const unknown = errors.filter((e) => e.code === 'unrecognized_keys');
        let removed = false;
        for (const { path: at, message } of unknown) {
          let target = body as Record<string, unknown>;
          for (const segment of at) target = target?.[segment] as Record<string, unknown>;
          for (const [, key] of message.matchAll(/"([^"]+)"/g)) {
            if (target && key in target) {
              delete target[key];
              dropped.push([...at, key].join('.'));
              removed = true;
            }
          }
        }
        if (!removed) throw error;
      }
    }
  }

  /**
   * A credential offer for the subject, with the subject's claims inline: pre-authorized code grant (with or without
   * `tx_code`), or authorization code grant with `issuer_state`, both at the built-in authorization server. EUDIPLO
   * always answers with an offer by reference (`credential_offer_uri`, resolvable once); for `byReference: false` the
   * adapter resolves it and hands out the offer by value (`credential_offer`).
   */
  async createOffer(req: CreateOfferRequest): Promise<CreatedOffer> {
    if (req.portraitOptOut) throw new Error('the ICS declares no portrait opt-out (ICS-17.portrait_opt_out): the PID configurations have no portrait');
    const unknown = req.configurations.filter((id) => !this.configurations.has(id));
    if (unknown.length) throw new Error(`the adapter configures no credential configuration ${unknown.join(', ')}`);
    // The subject's claims in the names of each configuration's format, with the ages and dates derived at issuance.
    const data = this.dataOf.get(req.subject) ?? req.subject;
    const claimsOf = (id: string) => {
      // Issue 27: `default_credential_A` for an Attestation Provider tenant.
      const attestation = this.attestations.get(id);
      if (attestation) return attestationClaimsFor(data, attestation.format);
      return pidClaimsFor(data, PID_CONFIGURATIONS[id].format, PID_CONFIGURATIONS[id].lifetime);
    };
    const preAuthorized = req.grant === 'pre-authorized_code';
    const txCode = preAuthorized && req.txCode ? String(randomInt(0, 1_000_000)).padStart(6, '0') : undefined;
    const deferralUrl = req.deferred ? await this.deferral() : undefined;
    const offer = await this.call<{ uri: string; session: string }>('POST', '/api/issuer/offer', {
      response_type: 'uri',
      flow: preAuthorized ? 'pre_authorized_code' : 'authorization_code',
      authorization_server: BUILT_IN_AS,
      credentialConfigurationIds: req.configurations,
      credentialClaims: Object.fromEntries(
        req.configurations.map((id) => [id, deferralUrl ? { type: 'webhook', webhook: { url: deferralUrl, auth: { type: 'none' } } } : { type: 'inline', claims: claimsOf(id) }]),
      ),
      ...(txCode ? { tx_code: txCode, tx_code_description: 'Transaction code of the conformance test' } : {}),
      reference: `${req.subject}`,
    });
    this.sessionsOf.set(req.subject, [...(this.sessionsOf.get(req.subject) ?? []), offer.session]);
    const uri = req.byReference ? offer.uri : await this.byValue(offer.uri);
    return { offer: uri, sessionId: offer.session, ...(txCode ? { txCode } : {}) };
  }

  /**
   * Issue 25 (`P-DEF`): the claims webhook of a deferred offer. EUDIPLO defers an issuance only when the claims come
   * from a webhook or attribute provider that answers `{ "deferred": true }` (inline claims never defer); this one
   * answers so for every request, on the host under `harnessHost`, which EUDIPLO reaches from its container.
   */
  private async deferral(): Promise<string> {
    if (!this.deferralWebhook) {
      const server = await startServer({ host: '0.0.0.0', port: 0 }, (_req, res) => sendJson(res, 200, { deferred: true, interval: DEFERRAL_INTERVAL_SECONDS }));
      this.deferralWebhook = { server, url: `http://${this.harnessHost}:${server.port}/claims` };
    }
    return this.deferralWebhook.url;
  }

  /** Completes a deferred issuance with the subject's claims (`POST /api/issuer/deferred/{transactionId}/complete`). */
  async completeDeferred(transactionId: string, subject: TestSubject): Promise<void> {
    const claims = this.category ? attestationClaimsFor(subject, 'SD') : pidClaimsFor(subject, 'SD', PID_LIFETIME_SECONDS);
    await this.call('POST', `/api/issuer/deferred/${encodeURIComponent(transactionId)}/complete`, { claims });
  }

  /**
   * The subject's authentication at the built-in authorization server (ICS-03.subject_authentication): it has no login
   * or consent step, the subject is the one whose claims the offer carries (bound by `issuer_state`), so the hook only
   * opens the authorization request and returns where EUDIPLO redirects to: the wallet's `redirect_uri` with `code`,
   * `state` and `iss`, or with `error`. An answer that is not a redirect (EUDIPLO answers a request without a pushed
   * `request_uri` with HTTP 409) is thrown as `AuthorizationEndpointError`.
   */
  async authenticateSubject(authorizationRequestUrl: string, _subject: TestSubject): Promise<string> {
    const response = await fetch(authorizationRequestUrl, { redirect: 'manual' });
    const location = response.headers.get('location');
    if (response.status >= 300 && response.status < 400 && location) return new URL(location, authorizationRequestUrl).toString();
    throw new AuthorizationEndpointError(response.status, await response.text(), Object.fromEntries(response.headers.entries()));
  }

  /** Resolves an offer by reference and returns it by value, with the same scheme. */
  private async byValue(uri: string): Promise<string> {
    const [scheme] = uri.split('?');
    const reference = new URLSearchParams(uri.slice(uri.indexOf('?') + 1)).get('credential_offer_uri');
    if (!reference) throw new Error(`EUDIPLO's offer has no credential_offer_uri: ${uri}`);
    const response = await fetch(reference);
    if (!response.ok) throw new Error(`EUDIPLO GET ${reference}: HTTP ${response.status} ${await response.text()}`);
    const offer = await response.json();
    return `${scheme}?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
  }

  /** The issuance configuration and the PID configuration as EUDIPLO stored them, to check what `setUp` configured. */
  async configuration(): Promise<{ issuance: Record<string, unknown>; pid: Record<string, unknown> }> {
    return {
      issuance: await this.call<Record<string, unknown>>('GET', '/api/issuer/config'),
      pid: await this.call<Record<string, unknown>>('GET', `/api/issuer/credentials/${PID_SD_JWT_CONFIGURATION}`),
    };
  }

  /** The tenant's status list settings (`GET /api/status-list-config`). */
  async statusListSettings(): Promise<Record<string, unknown>> {
    return this.call<Record<string, unknown>>('GET', '/api/status-list-config');
  }

  /** The status of every credential the session issued that carries a status entry. */
  async credentialStatus(sessionId: string): Promise<CredentialStatusEntry[]> {
    return this.call<CredentialStatusEntry[]>('GET', `/api/session/${sessionId}/credential-status`);
  }

  /**
   * Revokes, suspends or reinstates every credential the session issued (`POST /api/session/revoke`), and resolves once
   * `GET /api/session/{id}/credential-status` reports the new status for each. EUDIPLO answers 409 for a session that
   * has issued no credential with a status entry yet, and for any change of a revoked credential.
   */
  async setStatus(sessionId: string, status: 'revoked' | 'suspended' | 'valid'): Promise<{ at: string }> {
    const value = STATUS_VALUE[status];
    await this.revokeWithRetry(sessionId, value);
    const at = new Date().toISOString();
    const entries = await this.credentialStatus(sessionId);
    if (!entries.length) throw new Error(`EUDIPLO reports no credential with a status entry for session ${sessionId}`);
    const wrong = entries.filter((entry) => entry.status !== value);
    if (wrong.length) throw new Error(`EUDIPLO reports status ${wrong.map((e) => e.status).join(', ')} instead of ${value} for session ${sessionId}`);
    return { at };
  }

  /**
   * Issue 27: `POST /api/session/revoke`, repeated on HTTP 503. EUDIPLO answers 503 ("Could not generate current tokens
   * for status list") when other changes of the same status list keep its token regeneration from settling, which the
   * Attestation Provider tenants' parallel lifecycle test cases provoke. The entry is written before the regeneration
   * fails, so a credential that already has the new status counts as done; otherwise the call is repeated.
   */
  private async revokeWithRetry(sessionId: string, value: number): Promise<void> {
    for (let attempt = 1; ; attempt++) {
      try {
        await this.call('POST', '/api/session/revoke', { sessionId, status: value });
        return;
      } catch (error) {
        if (!(error instanceof EudiploError) || error.status !== 503 || attempt >= 5) throw error;
        await new Promise((resolve) => setTimeout(resolve, 500 * attempt));
        const entries = await this.credentialStatus(sessionId).catch(() => []);
        if (entries.length && entries.every((entry) => entry.status === value)) return;
      }
    }
  }

  /**
   * Issue 26 (PP_WS_SM_Revocation_008): the Provider's back office learns that the subject's data changed. EUDIPLO keeps
   * no subject record (the claims travel with each offer), so the adapter plays that part, as an integrator's identity
   * system would: it revokes every credential issued for the subject (`POST /api/session/revoke` per session; a session
   * that issued nothing with a status entry answers 409 and is skipped), and from now on offers for the subject carry
   * the data of `to`.
   */
  async changeSubject(from: TestSubject, to: TestSubject): Promise<void> {
    for (const sessionId of this.sessionsOf.get(from) ?? []) {
      try {
        await this.call('POST', '/api/session/revoke', { sessionId, status: STATUS_VALUE.revoked });
      } catch (error) {
        if (!(error instanceof EudiploError) || error.status !== 409) throw error;
      }
    }
    this.dataOf.set(from, to);
  }

  /**
   * Issue 27 (`AP_WS_SM_Revocation_102`, ICS-19): changes the embedded disclosure policy of every configuration the
   * session issued credentials of (`PATCH /api/issuer/credentials/{id}`: another allowed relying party), and resolves
   * once EUDIPLO stores the new policy. `revokeOnDisclosurePolicyChange=true` (EUDIPLO/eudiplo#1642) makes EUDIPLO
   * revoke every attestation issued under the old policy (EDP_11), so the test case issues from a configuration of its
   * own (`ICS-19.EDP.SD`); a release before it ignores the parameter.
   */
  async changeDisclosurePolicy(sessionId: string): Promise<{ at: string }> {
    const configurations = [...new Set((await this.credentialStatus(sessionId)).map((entry) => entry.credentialConfigurationId))];
    if (!configurations.length) throw new Error(`EUDIPLO reports no credential of session ${sessionId}`);
    const policy = { policy: 'allowList', values: [CHANGED_DISCLOSURE_POLICY_RP] };
    for (const id of configurations) {
      await this.call('PATCH', `/api/issuer/credentials/${encodeURIComponent(id)}?revokeOnDisclosurePolicyChange=true`, { embeddedDisclosurePolicy: policy });
      const stored = await this.call<{ embeddedDisclosurePolicy?: { values?: unknown[] } }>('GET', `/api/issuer/credentials/${encodeURIComponent(id)}`);
      if (!stored.embeddedDisclosurePolicy?.values?.includes(CHANGED_DISCLOSURE_POLICY_RP)) throw new Error(`EUDIPLO did not store the changed disclosure policy of ${id}`);
    }
    return { at: new Date().toISOString() };
  }

  /** Clears EUDIPLO's trust list cache, so the next wallet or key attestation makes it fetch `TL-WP` again. */
  async refreshTrust(): Promise<void> {
    await this.call('DELETE', '/api/cache/trust-list');
  }

  async describe(): Promise<Record<string, string>> {
    return {
      url: this.baseUrl,
      ...(this.version?.version ? { version: this.version.version } : {}),
      ...(this.version?.revision ? { revision: this.version.revision } : {}),
      ...(this.tenantId ? { tenant: this.tenantId } : {}),
      ...(this.method ? { enrolment: this.method === 'csr' ? 'CSR (GET /api/key-chain/{id}/csr)' : 'keys generated by the Registrar, imported (POST /api/key-chain/import)' } : {}),
      walletAttestationStatusCheckMode: this.capabilities.statusCheckMode ? 'strict' : 'not configurable (best effort)',
      revokeWithWalletUnit: this.capabilities.revokeWithWalletUnit ? 'on' : this.category ? 'off (ICS-07)' : 'not configurable',
      ...(this.category ? { category: CATEGORY_NAMES[this.category], credential: 'default_credential_A' } : {}),
    };
  }

  /** Deletes the tenant with its configurations, key chains and sessions. */
  async tearDown(): Promise<void> {
    await this.deferralWebhook?.server.close();
    this.deferralWebhook = undefined;
    if (this.tenantId && this.rootToken) await this.call('DELETE', `/api/tenant/${this.tenantId}`, undefined, this.rootToken);
    this.tenantId = undefined;
    this.token = undefined;
    this.keyChains = undefined;
    this.method = undefined;
    this.configurations.clear();
    this.sessionsOf.clear();
    this.dataOf.clear();
    this.attestations.clear();
    this.category = undefined;
  }
}

/** ARF Annex II reuse policy: method A (once only) with the batch size, then method B (limited time, one day before expiry). */
const reusePolicy = (batchSize: number) => ({
  id: 'arf_annex_ii',
  options: [
    { details: ['once_only'], batch_size: batchSize, reissue_trigger_unused: Math.max(0, batchSize - 1) },
    { details: ['limited_time'], reissue_trigger_lifetime_left: 86_400 },
  ],
});

const derOf = (pem: string) => pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, '');

export function createAdapter(): IssuerAdapter {
  return new IssuerEudiploAdapter();
}
