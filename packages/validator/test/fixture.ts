// The self-validation fixture (harness design section 7): the test PKI and lists of `default_trust_configuration_rp`
// served from memory, and one function that builds a presentation step exactly as the controller does (forge, fault
// layer, Conformance Wallet response) and runs the reference validator over it in `all` mode.
import { randomUUID } from 'node:crypto';
import {
  categoryOfCredentialQuery,
  type DcqlQuery,
  type DefaultQueryId,
  type Flow,
  faultsOf,
  type FaultId,
  faultInfo,
  type PresentationAction,
  type TrustListAction,
} from '@rp-conformance/core';
import {
  buildAuthorizationResponse,
  buildDcApiResponse,
  buildPresentation,
  buildVpToken,
  forgePresentations,
  heldCredentialOf,
  buildSealedLote,
  buildTrustedLists,
  buildTrustListVersion,
  buildRequest,
  issueRegistrationCertificate,
  requestAnchorKeyIds,
  trustedListEntitiesOf,
  createTestPki,
  defaultEntitiesOf,
  defaultQueries,
  type EcKeyPair,
  forgePresentation,
  type ForgedCredential,
  generateEcKeyPair,
  generateSecp256k1KeyPair,
  type HeldCredential,
  jwkThumbprint,
  LIST_PROFILES,
  type LoteListId,
  PID_DOCTYPE,
  PID_VCT,
  requestedElements,
  type Secp256k1KeyPair,
  type ServedStatusList,
  type TestPki,
} from '@rp-conformance/forge';
import { exportJWK, generateKeyPair, type JWK } from 'jose';
import type { CheckResult } from '@rp-conformance/core';
import {
  type FetchedStatusList,
  type MdocValidation,
  type SdJwtVcValidation,
  TRUST_RULES,
  TrustStore,
  type ValidationMode,
  validateAuthorizationResponse,
  validateMdocPresentation,
  validateCombinedBinding,
  validateRequests,
  validateSdJwtVcPresentation,
  validateVpToken,
} from '../src/index';

export const LISTS: LoteListId[] = ['TL-PID', 'TL-PUB', 'TL-WP', 'TL-AC', 'TL-RC'];
/** The grace period `G` of the reference validator in the self-validation (ICS RP.T.2 of the reference Relying Party). */
export const GRACE_MS = 60 * 60 * 1000;
export const AUDIENCE = 'x509_hash:self-validation';
export const SKEW = 60;
export const KB_MAX_AGE = 300;
export const MAX_STATUS_LIST_BYTES = 1 << 20;
/** The maximum response size of the reference validator in the self-validation (ICS RP.P.11 of the reference Relying Party). */
export const MAX_RESPONSE_BYTES = 1 << 20;
/** The freshness policy for Status List Tokens of the reference validator in the self-validation (ICS RP.R.7, RP.R.8). */
export const STATUS_LIST_FRESHNESS = { maxAgeSeconds: 7 * 24 * 3600, refuseFutureIat: true };
export const RESPONSE_URI = 'https://rp.rp-test/self-validation/response';
/** The Origin of the Relying Party's page in the DC API flow. */
export const ORIGIN = 'https://rp.rp-test';
const BASE = 'https://trust.rp-test/self-validation';
/** Where the fixture serves the lists in ETSI TS 119 612 format. */
export const TRUSTED_LIST_LOCATIONS = { LOTL: `${BASE}/LOTL.xml`, 'TL-QEAA': `${BASE}/TL-QEAA.xml` };

export interface Transaction {
  key: { kid: string; privateKey: CryptoKey; publicJwk: JWK };
  nonce: string;
  state: string;
}

export interface SelfValidation {
  forged: ForgedCredential;
  /** The transaction the step answered, and the `vp_token` entry presented in it. */
  transaction: Transaction;
  presentation: string;
  response: CheckResult[];
  credential?: SdJwtVcValidation | MdocValidation;
  /** Every failed check of the response and the credential. */
  failures: string[];
}

export class Fixture {
  readonly lists = new Map<string, string>();
  readonly statusLists = new Map<string, ServedStatusList>();
  trust!: TrustStore;
  queries!: Record<DefaultQueryId, DcqlQuery>;
  private sequence = 1;
  /** The sequence number of the latest version of each list, for a rollback. */
  private readonly latest = new Map<string, number>();

  private constructor(
    readonly pki: TestPki,
    readonly holder: EcKeyPair,
    readonly walletKey: EcKeyPair,
    readonly secp256k1: Secp256k1KeyPair,
  ) {}

  static async create(): Promise<Fixture> {
    const fixture = new Fixture(await createTestPki(), await generateEcKeyPair(), await generateEcKeyPair(), generateSecp256k1KeyPair());
    fixture.queries = defaultQueries(fixture.pki);
    const fetchList = (async (url: string) => {
      const body = fixture.lists.get(String(url));
      return new Response(body ?? 'not found', { status: body ? 200 : 404 });
    }) as typeof fetch;
    fixture.trust = new TrustStore(
      {
        lotes: LISTS.map((id) => ({
          id,
          url: `${BASE}/${id}`,
          loteType: LIST_PROFILES[id].loteType,
          schemeOperatorCertificatePem: fixture.pki.schemeOperators[id].certificate.pem,
        })),
        listOfTrustedLists: { url: TRUSTED_LIST_LOCATIONS.LOTL, signingCertificatesPem: [fixture.pki.trustedListOperators.LOTL.certificate.pem] },
        rulebooks: [{ credential: 'default_credential_eaa', anchorsPem: [fixture.pki.entities['EP-A'].anchors.issuance.certificate.pem] }],
      },
      fetchList,
      { graceMs: GRACE_MS },
    );
    for (const id of LISTS) await fixture.publish(id, undefined, false);
    const trustedLists = await buildTrustedLists({ pki: fixture.pki, locations: TRUSTED_LIST_LOCATIONS, sequenceNumber: fixture.sequence });
    fixture.latest.set('TL-QEAA', fixture.sequence++);
    fixture.lists.set(TRUSTED_LIST_LOCATIONS.LOTL, trustedLists.LOTL);
    fixture.lists.set(TRUSTED_LIST_LOCATIONS['TL-QEAA'], trustedLists['TL-QEAA']);
    await fixture.reload();
    return fixture;
  }

  /** Publishes a list (default: the entities of `default_trust_configuration_rp`) and reloads the trust store. */
  async publish(id: LoteListId, entities = defaultEntitiesOf(this.pki, id), reload = true) {
    const { jws } = await buildSealedLote({ list: id, pki: this.pki, entities, sequenceNumber: this.sequence });
    this.latest.set(id, this.sequence++);
    this.lists.set(`${BASE}/${id}`, jws);
    if (reload) await this.reload();
  }

  /**
   * Publishes the version of `TL-PID` or `TL-QEAA` a trust-list step publishes, as the harness does, and reloads the
   * trust store; returns the lists the store refused.
   */
  async publishVersion(action: TrustListAction, entities: string[]) {
    const version = await buildTrustListVersion(action, {
      pki: this.pki,
      entities,
      sequenceNumber: this.sequence++,
      previousSequenceNumber: this.latest.get(action.list) ?? 1,
      location: `${BASE}/${action.list}`,
      locations: TRUSTED_LIST_LOCATIONS,
      graceMs: GRACE_MS,
    });
    if (!action.faults?.includes('trust-list.rollback')) this.latest.set(action.list, version.sequenceNumber);
    this.lists.set(action.list === 'TL-QEAA' ? TRUSTED_LIST_LOCATIONS['TL-QEAA'] : `${BASE}/${action.list}`, version.body);
    return (await this.trust.refresh()).filter((r) => r.error);
  }

  /** Restores `TL-PID` and `TL-QEAA` of `default_trust_configuration_rp`. */
  async restore() {
    await this.publishVersion({ kind: 'trust-list', list: 'TL-QEAA' }, trustedListEntitiesOf(this.pki));
    await this.publish('TL-PID');
  }

  async reload() {
    const failed = (await this.trust.refresh()).filter((r) => r.error);
    if (failed.length) throw new Error(failed.map((f) => f.error).join('; '));
  }

  /** The registration certificate of the Relying Party, for every default query, as the harness issues it. */
  private registration?: Promise<string>;

  /**
   * Builds `count` requests of the reference Relying Party's form for a default query via `flow`, the first with
   * `fault` (or, for the faults that repeat an earlier request's value, the second), and runs the request checks over them.
   */
  async validateRequests(flow: Flow, query: DefaultQueryId, options: { count?: number; fault?: FaultId; requestUri?: 'twice' | 'post' } = {}) {
    this.registration ??= issueRegistrationCertificate(
      this.pki,
      Object.entries(this.queries)
        .filter(([id]) => !id.endsWith('_trusted_authorities'))
        .map(([, q]) => q),
    );
    const registrationCertificate = await this.registration;
    const count = Math.max(options.count ?? 1, options.fault === 'request.nonce-reused' || options.fault === 'request.enc-key-reused' ? 2 : 1);
    const captured = [];
    let first: Awaited<ReturnType<typeof buildRequest>> | undefined;
    for (let i = 0; i < count; i++) {
      const repeat = i === 1 && first;
      const built = await buildRequest({
        pki: this.pki,
        flow,
        query: this.queries[query],
        registrationCertificate,
        baseUrl: 'https://rp.rp-test',
        // The faults of the second retrieval and of the POST need that retrieval.
        requestUri: options.fault === 'request.refetch-refused' ? 'twice' : options.fault === 'request.wallet-nonce-missing' ? 'post' : flow === 'redirect' ? options.requestUri : undefined,
        ...(repeat && options.fault === 'request.nonce-reused' ? { nonce: first?.nonce } : {}),
        ...(repeat && options.fault === 'request.enc-key-reused' ? { encryptionJwk: first?.encryptionJwk } : {}),
        ...(i === 0 && options.fault && !['request.nonce-reused', 'request.enc-key-reused'].includes(options.fault) ? { fault: options.fault } : {}),
      });
      first ??= built;
      captured.push(built.captured);
    }
    return validateRequests(captured, {
      accessCertificateAnchors: [this.pki.entities['AC-A'].anchors.issuance.certificate],
      registrationCertificateAnchors: [this.pki.entities['RC-A'].anchors.issuance.certificate],
      trustedAuthorityKeyIds: requestAnchorKeyIds(this.pki),
      requireTrustedAuthorities: query.endsWith('_trusted_authorities'),
    });
  }

  async transaction(): Promise<Transaction> {
    const { publicKey, privateKey } = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
    const kid = `enc-${randomUUID()}`;
    return { key: { kid, privateKey: privateKey as CryptoKey, publicJwk: { ...(await exportJWK(publicKey)), kid, use: 'enc', alg: 'ECDH-ES' } }, nonce: randomUUID(), state: randomUUID() };
  }

  /**
   * Builds a presentation step and validates it in `all` mode, like the reference Relying Party but without stopping. The
   * flow is that of the step's response fault, if it has one of its own, or `options.flow` (default redirects): via the
   * DC API the KB-JWT is addressed to `origin:<origin>`, the mdoc SessionTranscript carries the DC API handover, and
   * the response is the `data` object of response mode `dc_api.jwt`, without `state`. With `presentation.replay` the
   * `vp_token` carries `options.replayed`, the presentation of an earlier step, or a valid presentation for
   * `options.other`.
   */
  async validate(
    action: PresentationAction,
    options: { mode?: ValidationMode; other?: Transaction; flow?: Flow; replayed?: string } = {},
  ): Promise<SelfValidation> {
    const mode = options.mode ?? 'all';
    const [fault] = faultsOf(action);
    const flow = (fault && faultInfo(fault).flow) || options.flow || 'redirect';
    const credentials = await forgePresentations(action, {
      pki: this.pki,
      holderPublicJwk: this.holder.publicJwk,
      holderSecp256k1PublicJwk: this.secp256k1.publicJwk,
      allocateStatusUri: () => `https://status.rp-test/self-validation/${randomUUID()}`,
      skewSeconds: SKEW,
    });
    const forged = credentials[0].forged;
    for (const [i, { forged: credential }] of credentials.entries()) {
      // A status list the Test Status Provider does not serve as a token (RP_PP_IA_Supportive) cannot be retrieved.
      const unserved = i === 0 && Boolean(action.statusList?.endpoint);
      if (credential.statusList && !unserved) this.statusLists.set(credential.statusList.uri, credential.statusList.served);
      if (credential.identifierList) this.statusLists.set(credential.identifierList.uri, credential.identifierList.served);
    }
    const tx = await this.transaction();
    const query = this.queries[action.query];
    const handover = flow === 'dc-api' ? ({ flow, origin: ORIGIN } as const) : ({ flow, clientId: AUDIENCE, responseUri: RESPONSE_URI } as const);
    const audience = flow === 'dc-api' ? `origin:${ORIGIN}` : AUDIENCE;
    const presentationFault = action.response.faults.find((f) => faultInfo(f).point === 'presentation');
    const vpTokenFault = action.response.faults.find((f) => faultInfo(f).point === 'vp-token');
    const replay = presentationFault === 'presentation.replay';
    if (replay && !options.other) throw new Error('presentation.replay needs another transaction');
    const boundTo = replay ? (options.other as Transaction) : tx;
    const held: HeldCredential[] = credentials.map(heldCredentialOf);
    const built = await buildVpToken(
      query,
      held,
      async (credential, requested, primary) =>
        (primary && replay && options.replayed) ||
        buildPresentation(
          credential,
          requested,
          {
            audience,
            clientId: AUDIENCE,
            nonce: primary ? boundTo.nonce : tx.nonce,
            handover,
            jwkThumbprint: await jwkThumbprint((primary ? boundTo : tx).key.publicJwk as JsonWebKey),
          },
          { holder: this.holder, secp256k1: this.secp256k1 },
          { fault: primary && !replay ? presentationFault : undefined, skewSeconds: SKEW, kbMaxAgeSeconds: KB_MAX_AGE },
        ),
      vpTokenFault,
    );
    const presentation = built.presentation;
    const responseFault = action.response.faults.find((f) => faultInfo(f).point === 'response');
    const encValues = ['A128GCM', 'A256GCM'];
    const state = flow === 'dc-api' ? undefined : tx.state;
    const input = {
      payload: { vp_token: built.vpToken, ...(state ? { state } : {}) },
      recipient: tx.key.publicJwk,
      enc: action.response.enc ?? 'A128GCM',
      walletKey: this.walletKey,
      otherTransactionKey: options.other?.key.publicJwk,
      maxResponseBytes: MAX_RESPONSE_BYTES,
    };
    const form = flow === 'dc-api' ? await buildDcApiResponse(input, responseFault) : await buildAuthorizationResponse(input, responseFault);
    const response = await validateAuthorizationResponse(form, { keys: [tx.key], encValues, state, mode, maxResponseBytes: MAX_RESPONSE_BYTES });
    const fetchList = async (uri: string): Promise<FetchedStatusList> => {
      const served = this.statusLists.get(uri);
      return served ? { status: 200, body: served.body, contentType: served.contentType } : { status: 404, body: '' };
    };
    const received = response.payload?.vp_token as Record<string, string[]> | undefined;
    // The vp_token as a whole: when it fails, the presentations in it are not validated (OpenID4VP section 8.6).
    const vpToken = received ? await validateVpToken(received, query, mode) : undefined;
    const validations: { id: string; result: SdJwtVcValidation | MdocValidation }[] = [];
    for (const credentialQuery of vpToken?.valid ? query.credentials : []) {
      for (const presented of received?.[credentialQuery.id] ?? []) {
        const common = {
          trust: this.trust,
          trustRule: TRUST_RULES[categoryOfCredentialQuery(credentialQuery.id)],
          nonce: tx.nonce,
          skewSeconds: SKEW,
          requireStatus: true,
          maxStatusListBytes: MAX_STATUS_LIST_BYTES,
          // The policies of the reference Relying Party (ICS RP.R.7, RP.R.8, RP.P.12, RP.P.13).
          statusListFreshness: STATUS_LIST_FRESHNESS,
          rejectPastExpiryDate: true,
          requireIssuerInCertificate: true,
          trustedAuthorities: credentialQuery.trusted_authorities,
          requestedClaims: credentialQuery.claims ?? [],
          mode,
        };
        const result =
          credentialQuery.format === 'mso_mdoc'
            ? await validateMdocPresentation(presented, {
                ...common,
                expectedDocType: (credentialQuery.meta?.doctype_value as string | undefined) ?? PID_DOCTYPE,
                handover,
                clientId: AUDIENCE,
                jwkThumbprint: await jwkThumbprint(tx.key.publicJwk as JsonWebKey),
                fetchStatusList: fetchList,
                fetchIdentifierList: fetchList,
              })
            : await validateSdJwtVcPresentation(presented, {
                ...common,
                expectedVct: (credentialQuery.meta?.vct_values as string[] | undefined) ?? [PID_VCT],
                audience,
                kbMaxAgeSeconds: KB_MAX_AGE,
                fetchStatusList: fetchList,
              });
        validations.push({ id: credentialQuery.id, result });
      }
    }
    // Attribute-based binding of a combined presentation, over the credentials whose disclosures could be read.
    const combined =
      validations.length > 1
        ? await validateCombinedBinding(
            validations
              .filter(({ result }) => result.claims)
              .map(({ id, result }) => ({ id, format: query.credentials.find((c) => c.id === id)?.format ?? '', claims: result.claims as Record<string, unknown> })),
            mode,
          )
        : undefined;
    const credential = validations[0]?.result;
    return {
      forged,
      transaction: tx,
      presentation,
      response: response.checks,
      credential,
      failures: [
        ...response.failures,
        ...(vpToken?.failures ?? []),
        ...validations.flatMap(({ result }) => result.failures),
        ...(combined?.failures ?? []),
      ],
    };
  }
}
