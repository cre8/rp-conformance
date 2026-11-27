// Template of an issuer adapter, for a PID Provider: copy this file, replace the HTTP calls to "my issuer" with the API
// of your Provider, and run it with
//
//   pnpm eudi-pcaf issuer run --adapter ./my-adapter.ts --ics my-ics.yaml
//
// The walkthrough is in adapter-guide.md, "Issuer adapters". The Provider API this template assumes is made up, and
// every call to it is marked `TODO`:
//
//   POST /admin/tenants/:tenant/enrolment          create the keys, answer their CSRs
//   PUT  /admin/tenants/:tenant                    configure the tenant (certificates, TL-WP, configurations, settings)
//   POST /admin/tenants/:tenant/offers             create a credential offer for a subject: { offer, sessionId, txCode? }
//   POST /admin/tenants/:tenant/sessions/:id/status       revoke, suspend or reinstate what a session issued
//   POST /admin/tenants/:tenant/deferred/:id/complete     complete a deferred issuance
//   POST /admin/tenants/:tenant/trust/refresh      fetch TL-WP now
//   DELETE /admin/tenants/:tenant                  remove the tenant
//   GET  /version                                  { version }
//
// The adapter is the only code of the harness that knows your Provider. The harness plays the wallet (its Wallet Units
// with their wallet and key attestations), the Wallet Provider, the Registrar that certifies your keys, and the trust
// lists. It runs the issuance itself, against your Provider's public OpenID4VCI endpoints, and checks every credential
// you issue. The adapter only does what a wallet cannot: enrol and configure the Provider, create offers, and act as its
// back office (authenticate the subject, change a credential's status).
import {
  AuthorizationEndpointError,
  type CreatedOffer,
  type CreateOfferRequest,
  type EnrolledCertificate,
  type EnrolmentRequest,
  type IssuerAdapter,
  type IssuerTestEnvironment,
  PID_TEST_SUBJECTS,
  pidClaimsOf,
  type TestSubject,
} from '@eudi-pcaf/core';

/** Where the harness reaches your Provider's admin API. Use 127.0.0.1, not localhost (adapter-guide.md, "Networking"). */
const ISSUER_URL = (process.env.MY_ISSUER_URL ?? 'http://127.0.0.1:8080').replace(/\/$/, '');
/** Whatever your admin API needs; pass it into the Docker image or the GitHub Action with `env-vars`. */
const ISSUER_TOKEN = process.env.MY_ISSUER_TOKEN;

/**
 * The credential configurations the test cases name. A test case names a configuration by its ICS item (for example
 * `ICS-02.SD`), and the ICS maps that to your configuration ID. The adapter creates each one the ICS names.
 */
const CONFIGURATIONS = [
  { ref: 'ICS-02.SD', format: 'SD', shortLived: false, profile: 'P-SD' },
  { ref: 'ICS-02.MD', format: 'MD', shortLived: false, profile: 'P-MD' },
  // A second SD-JWT VC configuration, which no PID offer names (PP_WS_MS_CredentialEndpoint_004_UF).
  { ref: 'ICS-02.second', format: 'SD', shortLived: false, profile: 'P-SD' },
  // Short-lived configurations (at most 24 hours, no status reference), with P-SHORT.
  { ref: 'ICS-05.short.SD', format: 'SD', shortLived: true, profile: 'P-SHORT' },
  { ref: 'ICS-05.short.MD', format: 'MD', shortLived: true, profile: 'P-SHORT' },
] as const;

type Format = 'SD' | 'MD';

export class MyIssuerAdapter implements IssuerAdapter {
  readonly name = 'my-issuer';
  /**
   * The host name under which your Provider reaches the harness's trust list and status list servers (TL-WP, the
   * status lists of the wallet attestations). 127.0.0.1 when it runs on the host; `host.docker.internal` when it runs in
   * a container. `--harness-host` overrides it.
   */
  readonly harnessHost = process.env.HARNESS_HOST ?? '127.0.0.1';
  private tenant?: string;
  /** The format of each configuration `setUp` created, by its ID. */
  private readonly formats = new Map<string, Format>();

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const response = await fetch(`${ISSUER_URL}${path}`, {
      method,
      headers: {
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...(ISSUER_TOKEN ? { authorization: `Bearer ${ISSUER_TOKEN}` } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await response.text();
    if (!response.ok) throw new Error(`my issuer ${method} ${path}: HTTP ${response.status} ${text}`);
    return (text ? JSON.parse(text) : undefined) as T;
  }

  private get base(): string {
    if (!this.tenant) throw new Error('the adapter is not set up');
    return `/admin/tenants/${encodeURIComponent(this.tenant)}`;
  }

  /**
   * Called once per run, before `setUp`, with the same namespace. Return CSRs (PKCS#10 PEM) for your Provider's keys;
   * the Test Registrar certifies them, and `setUp` gets the certificates. If your Provider cannot create CSRs, return
   * `undefined`: the Registrar then generates the keys, and `setUp` gets each certificate with its private key to import.
   */
  async enrol(namespace?: string): Promise<EnrolmentRequest | undefined> {
    if (!namespace) throw new Error('enrol needs the namespace');
    this.tenant = namespace;
    // TODO: replace with your Provider's API, or return undefined.
    const csrs = await this.call<{ sdJwtSigner: string; mdocSigner?: string; statusListSigner?: string; access: string }>(
      'POST',
      `${this.base}/enrolment`,
    );
    return {
      // The credential signing keys, each certified in the profile it signs: an SD-JWT VC issuance signer, or an mdoc
      // document signer (ISO/IEC 18013-5 Annex B).
      credentialSigning: [csrs.sdJwtSigner, ...(csrs.mdocSigner ? [csrs.mdocSigner] : [])],
      credentialSigningProfiles: ['sd-jwt-vc', ...(csrs.mdocSigner ? (['mdoc'] as const) : [])],
      // Leave it out when your Provider signs its status lists with the credential signing key.
      ...(csrs.statusListSigner ? { statusListSigning: csrs.statusListSigner } : {}),
      access: csrs.access,
    };
  }

  /**
   * Called once per run. `namespace` is new for every run: the URL of TL-WP contains it, so a configuration left from an
   * earlier run cannot be mistaken for this one. `env.ics` is the ICS the run uses.
   */
  async setUp(env: IssuerTestEnvironment, namespace: string): Promise<void> {
    this.tenant = namespace;
    const profiles = env.credentialSigningProfiles ?? env.credentialSigningCertificates.map(() => 'sd-jwt-vc' as const);
    const signerFor = (profile: 'sd-jwt-vc' | 'mdoc') => env.credentialSigningCertificates[profiles.indexOf(profile)];
    const tlWp = env.trustLists.find((list) => list.id === 'TL-WP');
    if (!tlWp) throw new Error('TL-WP is not published');

    // The configurations the ICS names, for the profiles it declares.
    this.formats.clear();
    const configurations = CONFIGURATIONS.filter((c) => env.ics.profiles.includes(c.profile) && typeof env.ics.items[c.ref] === 'string').map((c) => {
      const id = String(env.ics.items[c.ref]);
      this.formats.set(id, c.format);
      return {
        id,
        format: c.format === 'SD' ? 'dc+sd-jwt' : 'mso_mdoc',
        // PID Rulebook: `vct` of the SD-JWT VC, docType and namespace of the mdoc.
        ...(c.format === 'SD' ? { vct: 'urn:eudi:pid:1' } : { docType: 'eu.europa.ec.eudi.pid.1' }),
        // A short-lived credential carries no status reference; any other one does (P-REV).
        shortLived: c.shortLived,
        lifetime: String(env.ics.items[c.shortLived ? 'ICS-05.short.validity_period' : 'ICS-05.validity_period'] ?? ''),
      };
    });

    // TODO: replace with your Provider's configuration API.
    await this.call('PUT', this.base, {
      // The certificates the Test Registrar issued: for your CSRs (chainPem only), or with the keys it generated
      // (privateKeyPem too). chainPem is leaf first, without the trust anchor.
      certificates: {
        sdJwtSigner: certificate(signerFor('sd-jwt-vc')),
        ...(profiles.includes('mdoc') ? { mdocSigner: certificate(signerFor('mdoc')) } : {}),
        ...(env.statusListSigningCertificate ? { statusListSigner: certificate(env.statusListSigningCertificate) } : {}),
        access: certificate(env.accessCertificate),
      },
      // The Wallet Providers it accepts wallet and key attestations from: TL-WP only, pinned to its scheme operator
      // certificate. The trust list test cases publish versions sealed by another key, stale or rolled back.
      walletProviderTrustList: { url: tlWp.url, signerCertificatePem: tlWp.schemeOperatorCertificatePem },
      // Published in its metadata (ETSI TS 119 475).
      registrationCertificate: env.registrationCertificate,
      configurations,
      // The ICS describes the Provider. Where your Provider has a setting for an item, set it from the ICS here; where it
      // has a fixed value, declare that value in the ICS instead.
      settings: {
        batchSize: Number(env.ics.items['ICS-08.batch_size'] ?? 1),
        statusListMinEntries: Number(env.ics.items['ICS-16.min_entries'] ?? 10_000),
        keyAttestationLevels: {
          keyStorage: list(env.ics.items['ICS-04.key_storage'], ['iso_18045_high']),
          userAuthentication: list(env.ics.items['ICS-04.user_authentication'], ['iso_18045_high']),
        },
        // A PID Provider rejects a wallet or key attestation whose status it cannot obtain (ICS-18).
        rejectUnknownAttestationStatus: !/^accept/i.test(String(env.ics.items['ICS-18'] ?? 'reject')),
      },
    });
  }

  /**
   * Create a credential offer for the test subject, for the configurations `req.configurations` names (your IDs, from
   * the ICS). Return the offer as your Provider hands it to a wallet: `openid-credential-offer://?credential_offer=…` by
   * value, or `…?credential_offer_uri=…` by reference, as `req.byReference` asks.
   */
  async createOffer(req: CreateOfferRequest): Promise<CreatedOffer> {
    if (req.portraitOptOut) throw new Error('this adapter does not offer the portrait opt-out (ICS-17.portrait_opt_out)');
    const unknown = req.configurations.filter((id) => !this.formats.has(id));
    if (unknown.length) throw new Error(`setUp created no configuration ${unknown.join(', ')}`);
    // TODO: replace with your Provider's API.
    const created = await this.call<{ offer: string; sessionId: string; txCode?: string }>('POST', `${this.base}/offers`, {
      configurations: req.configurations,
      grant: req.grant, // 'pre-authorized_code' or 'authorization_code'
      byReference: req.byReference,
      // Pre-authorized code with a transaction code: return the code you set, the harness enters it.
      txCode: req.grant === 'pre-authorized_code' && Boolean(req.txCode),
      // Deferred issuance (P-DEF): answer the credential request with 202 until `completeDeferred` is called.
      deferred: Boolean(req.deferred),
      // The subject's data, as your Provider's identity source would provide it. The Conformance Wallet compares every
      // issued value with these (ICS-17). If your Provider takes the data from its own records instead, seed SUBJ-1 and
      // SUBJ-2 there with these values and send only the subject. The Provider adds the issuance metadata and the age
      // attributes itself.
      subject: req.subject,
      claims: Object.fromEntries(req.configurations.map((id) => [id, subjectClaims(req.subject, this.formats.get(id) ?? 'SD')])),
    });
    return { offer: created.offer, sessionId: created.sessionId, ...(created.txCode ? { txCode: created.txCode } : {}) };
  }

  /**
   * Authorization code grant (P-AC): complete the subject's authentication for the authorization request the wallet
   * opened, and return the URL your Authorization Server redirects to (the wallet's `redirect_uri` with `code`, `state`
   * and `iss`, or with `error`). This template follows the redirect of an Authorization Server without a login step. If
   * yours has a login, drive it here (for example a test identity provider that logs in the subject).
   */
  async authenticateSubject(authorizationRequestUrl: string, _subject: TestSubject): Promise<string> {
    // TODO: log in the subject, if your Authorization Server asks for it.
    const response = await fetch(authorizationRequestUrl, { redirect: 'manual' });
    const location = response.headers.get('location');
    if (response.status >= 300 && response.status < 400 && location) return new URL(location, authorizationRequestUrl).toString();
    // Not a redirect to the client: the issuance client records it as the authorization endpoint's answer.
    throw new AuthorizationEndpointError(response.status, await response.text(), Object.fromEntries(response.headers.entries()));
  }

  /**
   * Revocation (P-HOOK): revoke, suspend or reinstate every credential the session issued. Resolve only once your
   * Provider reports the change done; the harness then expects it on the status list within `T_rev` (ICS-06.T_rev).
   */
  async setStatus(sessionId: string, status: 'revoked' | 'suspended' | 'valid'): Promise<{ at: string }> {
    // TODO: replace with your Provider's API, or remove the method (then P-HOOK is not applicable).
    await this.call('POST', `${this.base}/sessions/${encodeURIComponent(sessionId)}/status`, { status });
    return { at: new Date().toISOString() };
  }

  /** Deferred issuance (P-DEF): complete the issuance, so the wallet's next poll returns the credential. */
  async completeDeferred(transactionId: string, subject: TestSubject): Promise<void> {
    // TODO: replace with your Provider's API, or remove the method (and do not declare P-DEF).
    await this.call('POST', `${this.base}/deferred/${encodeURIComponent(transactionId)}/complete`, {
      subject,
      claims: subjectClaims(subject, 'SD'),
    });
  }

  /**
   * Optional. The trust list test cases publish a new version of TL-WP and wait for your Provider to use it: with this
   * hook they wait briefly after calling it, without it the refresh interval the ICS declares (ICS-15.T_refresh).
   */
  async refreshTrust(): Promise<void> {
    // TODO: replace with your Provider's API, or remove the method.
    await this.call('POST', `${this.base}/trust/refresh`);
  }

  /** Optional. Recorded in the report: which build of your Provider was tested. */
  async describe(): Promise<Record<string, string>> {
    // TODO: replace with your Provider's API, or remove the method.
    const { version } = await this.call<{ version?: string }>('GET', '/version').catch(() => ({ version: undefined }));
    return { url: ISSUER_URL, ...(version ? { version } : {}), ...(this.tenant ? { tenant: this.tenant } : {}) };
  }

  /** Optional. Called after the last test case. */
  async tearDown(): Promise<void> {
    // TODO: replace with your Provider's API, or remove the method.
    if (this.tenant) await this.call('DELETE', this.base).catch(() => undefined);
  }

  // Not implemented, so the test cases that need them are NOT APPLICABLE: `changeSubject` (the subject's data change in
  // your records, PP_WS_SM_Revocation_008) and `changeDisclosurePolicy` (Attestation Providers with an embedded
  // disclosure policy, P-EDP). See adapter-guide.md, "Issuer adapters".
}

/** A certificate as the template's made-up API takes it. */
function certificate(cert: EnrolledCertificate | undefined) {
  if (!cert) throw new Error('the Test Registrar issued no certificate for a key the ICS needs');
  return { chainPem: cert.chainPem, ...(cert.privateKeyPem ? { privateKeyPem: cert.privateKeyPem } : {}) };
}

/**
 * The subject's PID data, in the claim names of the format (PID Rulebook: chapter 5 for SD-JWT VC, 4 for mdoc). An
 * Attestation Provider issues `default_credential_A` instead: its values are `ATTESTATION_TEST_SUBJECTS` of
 * `@eudi-pcaf/core`.
 */
function subjectClaims(subject: TestSubject, format: Format): Record<string, unknown> {
  return pidClaimsOf(PID_TEST_SUBJECTS[subject], format);
}

/** A declared ICS value as a list of strings. */
function list(value: unknown, fallback: string[]): string[] {
  if (value === undefined) return fallback;
  return Array.isArray(value) ? value.map(String) : [String(value)];
}

/** The harness calls this to get the adapter; the module must export it. */
export function createAdapter(): IssuerAdapter {
  return new MyIssuerAdapter();
}
