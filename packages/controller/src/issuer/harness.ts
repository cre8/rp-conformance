// The harness services of an issuer run (issuer harness design sections 3 and 5.3): the test PKI, the Test Status
// Provider (`SL-WP-A`, `SL-WP-B`), the Test Trust Infrastructure (`TL-WP`, `TL-PID`, `TL-AC`, `TL-RC`), the Test Wallet
// Provider with its Wallet Units, and the enrolment of the Provider under test by the Test Registrar.
import { CATEGORY_ENTITIES, ATTESTATION_DOCTYPE, ATTESTATION_VCT, type CredentialSigningProfile, durationMs, type IssuerAdapter, type ProviderCategory, type PublishedListOfTrustedLists, type RulebookTrust, type IssuerIcs, type IssuerTestEnvironment, type IssuerTrustListAction, type PublishedTrustList } from '@eudi-pcaf/core';
import { buildSealedLote, buildTrustedLists, buildTrustListVersion, TRUSTED_LIST_MEDIA_TYPE, createTestPki, type Enrolment, enrolSut, LIST_PROFILES, type LoteListId, PID_DOCTYPE, PID_VCT, type TestPki, toEnrolledCertificate } from '@eudi-pcaf/forge';
import { StatusProvider } from '@eudi-pcaf/status-provider';
import { TrustInfrastructure } from '@eudi-pcaf/trust-infrastructure';
import { type TrustRule, TRUST_RULES, TrustStore } from '@eudi-pcaf/validator';
import { publishTlWp, TestWalletProvider, tlWpEntities } from '@eudi-pcaf/wallet-provider';

/** What the access certificate from `AC-A` names for the Provider under test (`default_configuration_PP_1`). */
export const PROVIDER_ACCESS = { entityIdentifier: 'VATDE-987654321', serviceIdentifier: 'S1', tradeName: 'PID Provider under conformance test' };

export interface IssuerHarnessOptions {
  runId: string;
  namespace: string;
  /** Host name under which the Provider reaches the harness services. */
  harnessHost: string;
  bindHost?: string;
  ics: IssuerIcs;
  /** Issue 27: the category of the Provider instance (default `PID`): the entity it is enrolled as and its root of trust. */
  category?: ProviderCategory;
}

export interface IssuerHarness {
  pki: TestPki;
  status: StatusProvider;
  trust: TrustInfrastructure;
  twp: TestWalletProvider;
  namespace: string;
  /** Issue 27: the Provider's category, the trust rule its credentials are validated with, and the matched entity name. */
  category: ProviderCategory;
  trustRule: TrustRule;
  issuerName: string;
  /** Issue 27: what a Relying Party trusts besides the LoTEs (the reference RP of a `present` step). */
  relyingPartyTrust?: { listOfTrustedLists?: PublishedListOfTrustedLists; rulebooks?: RulebookTrust[] };
  /** Set by `enrol`. */
  env?: IssuerTestEnvironment;
  enrolment?: Enrolment;
  /** The reference validator's trust configuration: `TL-PID` as published after enrolment. */
  trustStore?: TrustStore;
  /** `fetch` for the harness itself: URLs under the harness host go to the local services. */
  fetch: typeof fetch;
  /**
   * Enrols the Provider (Test Registrar, design section 5.3) through the adapter's `enrol`, publishes `TL-PID` with
   * `PP-T` as enrolled, and builds the environment `setUp` gets.
   */
  enrol(adapter: IssuerAdapter): Promise<IssuerTestEnvironment>;
  /**
   * Issue 26: publishes a version of `TL-WP` (`trust-list` step): the default entities with the step's changes and at
   * most one trust-list fault, under the next sequence number (one lower than the latest for `trust-list.rollback`).
   * Without an action, the default version again under the next sequence number (restoring trust after a test case).
   */
  publishTlWp(action?: IssuerTrustListAction): Promise<{ version: number; sequenceNumber: number; entities: string[]; publishedAt: Date }>;
  stop(): Promise<void>;
}

/**
 * The credential types of the registration certificate: the PID, or for an Attestation Provider `default_credential_A`
 * (issue 27), in every format the ICS declares (ICS-02).
 */
function providedAttestations(ics: IssuerIcs, category: ProviderCategory = 'PID') {
  const vct = category === 'PID' ? PID_VCT : ATTESTATION_VCT;
  const doctype = category === 'PID' ? PID_DOCTYPE : ATTESTATION_DOCTYPE;
  return [
    ...(ics.profiles.includes('P-SD') ? [{ format: 'dc+sd-jwt', meta: { vct_values: [vct] } }] : []),
    ...(ics.profiles.includes('P-MD') ? [{ format: 'mso_mdoc', meta: { doctype_value: doctype } }] : []),
  ];
}

/** Issue 27: the trust rule of each category (`TRUST_RULES` of the reference validator). */
const CATEGORY_TRUST_RULES: Record<ProviderCategory, TrustRule> = { PID: TRUST_RULES.pid, Q: TRUST_RULES.qeaa, PB: TRUST_RULES['pub-eaa'], E: TRUST_RULES.eaa };
/** The rulebook of `default_credential_A` as a non-qualified EAA (`TA-EAA`): the reference validator's rulebook ID. */
const EAA_RULEBOOK = 'default_credential_eaa';

/**
 * Starts the harness services of an issuer run. The Provider gets only the scheme operator certificates: it derives
 * Wallet Provider trust from `TL-WP` (catalogue section 3.2).
 */
export async function startIssuerHarness(options: IssuerHarnessOptions): Promise<IssuerHarness> {
  const pki = await createTestPki();
  const bind = options.bindHost ?? '0.0.0.0';
  const status = await new StatusProvider().start({ host: bind, port: 0, publicHost: options.harnessHost });
  const trust = await new TrustInfrastructure().start({ host: bind, port: 0, publicHost: options.harnessHost });
  // The harness reaches its own services on the loopback interface, whatever name the Provider uses for them.
  const local = (url: string) => {
    for (const service of [status.baseUrl, trust.baseUrl]) {
      const port = new URL(service).port;
      const prefix = `http://${options.harnessHost}:${port}`;
      if (url.startsWith(prefix)) return `http://127.0.0.1:${port}${url.slice(prefix.length)}`;
    }
    return url;
  };
  const localFetch: typeof fetch = (input, init) => fetch(typeof input === 'string' ? local(input) : input instanceof URL ? local(input.href) : input, init);
  const twp = await TestWalletProvider.create({ pki, statusProvider: status, runId: options.namespace });
  const tlWp = await publishTlWp(trust, options.namespace, pki);

  const loteType = (list: LoteListId) => LIST_PROFILES[list].loteType;
  const describe = (id: LoteListId, url: string): PublishedTrustList => ({
    id,
    loteType: loteType(id),
    url,
    schemeOperatorCertificatePem: pki.schemeOperators[id].certificate.pem,
  });

  // Issue 26: sequence numbers of `TL-WP` count up; a rolled back version does not become the latest one.
  let tlWpSequence = 1;
  let tlWpLatest = tlWpSequence;
  const graceMs = durationMs(String(options.ics.items['ICS-15.next_update_grace'] ?? '')) ?? 0;

  const category = options.category ?? 'PID';
  const { entity } = CATEGORY_ENTITIES[category];
  const harness: IssuerHarness = {
    pki,
    category,
    trustRule: CATEGORY_TRUST_RULES[category],
    issuerName: category === 'E' ? `rulebook of ${EAA_RULEBOOK}` : entity,
    status,
    trust,
    twp,
    namespace: options.namespace,
    fetch: localFetch,
    async enrol(adapter) {
      const csrs = await adapter.enrol(options.namespace);
      const signingProfiles: CredentialSigningProfile[] = csrs
        ? (csrs.credentialSigningProfiles ?? csrs.credentialSigning.map(() => 'sd-jwt-vc' as const))
        : ['sd-jwt-vc', ...(options.ics.profiles.includes('P-MD') ? (['mdoc'] as const) : [])];
      const enrolment = await enrolSut(pki, {
        entity,
        ...(csrs ? { csrs } : {}),
        // With CSRs the adapter names the format of each key (default SD-JWT VC); without, the Registrar generates an
        // SD-JWT VC signer, and an mdoc document signer when the ICS declares mdoc (P-MD).
        credentialSigningProfiles: signingProfiles,
        statusListWithIssuanceKey: csrs ? !csrs.statusListSigning : false,
        access: category === 'PID' ? PROVIDER_ACCESS : { ...PROVIDER_ACCESS, tradeName: `${CATEGORY_ENTITIES[category].name} under conformance test` },
        registration: { providesAttestations: providedAttestations(options.ics, category) },
      });
      // PP-T is published as enrolled (its revocation anchor may have become its issuance anchor).
      const lists: PublishedTrustList[] = [describe('TL-WP', tlWp.url)];
      // Issue 27: `TL-PUB` for a PuB-EAA Provider (`PB-T`).
      for (const id of ['TL-PID', 'TL-AC', 'TL-RC', ...(category === 'PB' ? ['TL-PUB'] : [])] as LoteListId[]) {
        const sealed = await buildSealedLote({ list: id, pki, distributionPoint: trust.urlOf(options.namespace, id) });
        lists.push(describe(id, trust.publish(options.namespace, id, sealed.jws).url));
      }
      // Issue 27: the LOTL and `TL-QEAA` with `QP-T` for a QEAA Provider; the rulebook anchor of `EP-T` for a
      // non-qualified EAA Provider, whose rulebook defines the anchor of its attestations and status lists.
      if (category === 'Q') {
        // Only the harness and its reference Relying Party read these lists, never the Provider: loopback URLs.
        const loopback = (url: string) => url.replace(`://${options.harnessHost}:`, '://127.0.0.1:');
        const locations = { LOTL: loopback(trust.urlOf(options.namespace, 'LOTL.xml')), 'TL-QEAA': loopback(trust.urlOf(options.namespace, 'TL-QEAA.xml')) };
        const built = await buildTrustedLists({ pki, locations, sequenceNumber: 1 });
        trust.publish(options.namespace, 'LOTL.xml', built.LOTL, TRUSTED_LIST_MEDIA_TYPE);
        trust.publish(options.namespace, 'TL-QEAA.xml', built['TL-QEAA'], TRUSTED_LIST_MEDIA_TYPE);
        harness.relyingPartyTrust = {
          listOfTrustedLists: { url: locations.LOTL, signingCertificatesPem: [pki.trustedListOperators.LOTL.certificate.pem], pointers: [{ id: 'TL-QEAA', url: locations['TL-QEAA'], schemeTerritory: 'DE' }] },
        };
      }
      if (category === 'E') harness.relyingPartyTrust = { rulebooks: [{ credential: EAA_RULEBOOK, anchorsPem: [pki.entities['EP-T'].anchors.issuance.certificate.pem] }] };
      const env: IssuerTestEnvironment = {
        runId: options.runId,
        trustLists: lists,
        credentialSigningCertificates: enrolment.credentialSigners.map(toEnrolledCertificate),
        credentialSigningProfiles: enrolment.credentialSigners.map((signer) => signer.profile),
        ...(enrolment.statusListSigner ? { statusListSigningCertificate: toEnrolledCertificate(enrolment.statusListSigner) } : {}),
        accessCertificate: toEnrolledCertificate(enrolment.access),
        registrationCertificate: enrolment.registrationCertificate,
        ics: options.ics,
      };
      const lote = (id: string) => {
        const list = lists.find((l) => l.id === id) as PublishedTrustList;
        return { id: list.id, url: list.url, loteType: list.loteType, schemeOperatorCertificatePem: list.schemeOperatorCertificatePem };
      };
      // Issue 27: the root of trust of the Provider's category besides `TL-PID`.
      const rp = harness.relyingPartyTrust;
      const trustStore = new TrustStore(
        {
          lotes: [lote('TL-PID'), ...(category === 'PB' ? [lote('TL-PUB')] : [])],
          ...(rp?.listOfTrustedLists ? { listOfTrustedLists: { url: rp.listOfTrustedLists.url, signingCertificatesPem: rp.listOfTrustedLists.signingCertificatesPem } } : {}),
          ...(rp?.rulebooks ? { rulebooks: rp.rulebooks } : {}),
        },
        localFetch,
      );
      const refreshed = await trustStore.refresh();
      const refused = refreshed.filter((r) => r.error);
      if (refused.length) throw new Error(`the reference validator refused ${refused.map((r) => `${r.id}: ${r.error}`).join('; ')}`);
      Object.assign(harness, { env, enrolment, trustStore });
      return env;
    },
    async publishTlWp(action) {
      const entities = tlWpEntities(pki, 1).filter((id) => !action?.remove?.includes(id));
      for (const id of action?.add ?? []) if (!entities.includes(id)) entities.push(id);
      tlWpSequence += 1;
      const built = await buildTrustListVersion(action ?? { kind: 'trust-list', list: 'TL-WP' }, {
        pki,
        entities,
        sequenceNumber: tlWpSequence,
        previousSequenceNumber: tlWpLatest,
        location: trust.urlOf(options.namespace, 'TL-WP'),
        graceMs,
      });
      if (!action?.faults?.includes('trust-list.rollback')) tlWpLatest = built.sequenceNumber;
      const publishedAt = new Date();
      const { version } = trust.publish(options.namespace, 'TL-WP', built.body, built.contentType);
      return { version, sequenceNumber: built.sequenceNumber, entities, publishedAt };
    },
    async stop() {
      await status.stop();
      await trust.stop();
    },
  };
  return harness;
}

/** The trust rule of the Provider's category: a PID Provider's credentials chain to `PP-T` on `TL-PID`. */
export const PID_TRUST_RULE = TRUST_RULES.pid;
export { CATEGORY_TRUST_RULES };
