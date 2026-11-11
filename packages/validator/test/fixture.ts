// The self-validation fixture (harness design section 7): the test PKI and lists of `default_trust_configuration_rp`
// served from memory, and one function that builds a presentation step exactly as the controller does (forge, fault
// layer, Conformance Wallet response) and runs the reference validator over it in `all` mode.
import { randomUUID } from 'node:crypto';
import { type DcqlQuery, type DefaultQueryId, type Flow, faultsOf, faultInfo, type PresentationAction } from '@rp-conformance/core';
import {
  buildAuthorizationResponse,
  buildDcApiResponse,
  buildSealedLote,
  createTestPki,
  defaultEntitiesOf,
  defaultQueries,
  type EcKeyPair,
  encodeDeviceResponse,
  forgePresentation,
  type ForgedCredential,
  generateEcKeyPair,
  jwkThumbprint,
  LIST_PROFILES,
  type LoteListId,
  PID_DOCTYPE,
  PID_VCT,
  presentMdoc,
  presentSdJwtVc,
  requestedElements,
  type ServedStatusList,
  type TestPki,
} from '@rp-conformance/forge';
import { exportJWK, generateKeyPair, type JWK } from 'jose';
import type { CheckResult } from '@rp-conformance/core';
import {
  type FetchedStatusList,
  type MdocValidation,
  type SdJwtVcValidation,
  TrustStore,
  type ValidationMode,
  validateAuthorizationResponse,
  validateMdocPresentation,
  validateSdJwtVcPresentation,
} from '../src/index';

export const LISTS: LoteListId[] = ['TL-PID', 'TL-PUB', 'TL-WP', 'TL-AC', 'TL-RC'];
export const AUDIENCE = 'x509_hash:self-validation';
export const SKEW = 60;
export const KB_MAX_AGE = 300;
export const MAX_STATUS_LIST_BYTES = 1 << 20;
export const RESPONSE_URI = 'https://rp.rp-test/self-validation/response';
/** The Origin of the Relying Party's page in the DC API flow. */
export const ORIGIN = 'https://rp.rp-test';
const BASE = 'https://trust.rp-test/self-validation';

export interface Transaction {
  key: { kid: string; privateKey: CryptoKey; publicJwk: JWK };
  nonce: string;
  state: string;
}

export interface SelfValidation {
  forged: ForgedCredential;
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

  private constructor(
    readonly pki: TestPki,
    readonly holder: EcKeyPair,
    readonly walletKey: EcKeyPair,
  ) {}

  static async create(): Promise<Fixture> {
    const fixture = new Fixture(await createTestPki(), await generateEcKeyPair(), await generateEcKeyPair());
    fixture.queries = defaultQueries(fixture.pki);
    const fetchList = (async (url: string) => {
      const body = fixture.lists.get(String(url));
      return new Response(body ?? 'not found', { status: body ? 200 : 404 });
    }) as typeof fetch;
    fixture.trust = new TrustStore(
      LISTS.map((id) => ({
        id,
        url: `${BASE}/${id}`,
        loteType: LIST_PROFILES[id].loteType,
        schemeOperatorCertificatePem: fixture.pki.schemeOperators[id].certificate.pem,
      })),
      fetchList,
    );
    for (const id of LISTS) await fixture.publish(id, undefined, false);
    await fixture.reload();
    return fixture;
  }

  /** Publishes a list (default: the entities of `default_trust_configuration_rp`) and reloads the trust store. */
  async publish(id: LoteListId, entities = defaultEntitiesOf(this.pki, id), reload = true) {
    const { jws } = await buildSealedLote({ list: id, pki: this.pki, entities, sequenceNumber: this.sequence++ });
    this.lists.set(`${BASE}/${id}`, jws);
    if (reload) await this.reload();
  }

  async reload() {
    const failed = (await this.trust.refresh()).filter((r) => r.error);
    if (failed.length) throw new Error(failed.map((f) => f.error).join('; '));
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
   * the response is the `data` object of response mode `dc_api.jwt`, without `state`.
   */
  async validate(action: PresentationAction, options: { mode?: ValidationMode; other?: Transaction; flow?: Flow } = {}): Promise<SelfValidation> {
    const mode = options.mode ?? 'all';
    const [fault] = faultsOf(action);
    const flow = (fault && faultInfo(fault).flow) || options.flow || 'redirect';
    const forged = await forgePresentation(action, {
      pki: this.pki,
      holderPublicJwk: this.holder.publicJwk,
      allocateStatusUri: () => `https://status.rp-test/self-validation/${randomUUID()}`,
      skewSeconds: SKEW,
    });
    if (forged.statusList) this.statusLists.set(forged.statusList.uri, forged.statusList.served);
    if (forged.identifierList) this.statusLists.set(forged.identifierList.uri, forged.identifierList.served);
    const tx = await this.transaction();
    const query = this.queries[action.query];
    const credentialQuery = query.credentials[0];
    const handover = flow === 'dc-api' ? ({ flow, origin: ORIGIN } as const) : ({ flow, clientId: AUDIENCE, responseUri: RESPONSE_URI } as const);
    const audience = flow === 'dc-api' ? `origin:${ORIGIN}` : AUDIENCE;
    const presentation =
      forged.format === 'mso_mdoc'
        ? encodeDeviceResponse(
            await presentMdoc(forged.credential as Uint8Array, {
              holderPrivateKey: this.holder.privateKey,
              handover,
              nonce: tx.nonce,
              jwkThumbprint: await jwkThumbprint(tx.key.publicJwk as JsonWebKey),
              elements: requestedElements(credentialQuery.claims),
            }),
          )
        : await presentSdJwtVc(forged.credential as string, {
            holderPrivateKey: this.holder.privateKey,
            disclose: (credentialQuery.claims ?? []).map((c) => String(c.path[0])),
            audience,
            nonce: tx.nonce,
          });
    const encValues = ['A128GCM', 'A256GCM'];
    const state = flow === 'dc-api' ? undefined : tx.state;
    const input = {
      payload: { vp_token: { [credentialQuery.id]: [presentation] }, ...(state ? { state } : {}) },
      recipient: tx.key.publicJwk,
      enc: action.response.enc ?? 'A128GCM',
      walletKey: this.walletKey,
      otherTransactionKey: options.other?.key.publicJwk,
    };
    const form = flow === 'dc-api' ? await buildDcApiResponse(input, action.response.faults[0]) : await buildAuthorizationResponse(input, action.response.faults[0]);
    const response = await validateAuthorizationResponse(form, { keys: [tx.key], encValues, state, mode });
    const presented = (response.payload?.vp_token as Record<string, string[]> | undefined)?.[credentialQuery.id]?.[0];
    const fetchList = async (uri: string): Promise<FetchedStatusList> => {
      const served = this.statusLists.get(uri);
      return served ? { status: 200, body: served.body, contentType: served.contentType } : { status: 404, body: '' };
    };
    const common = {
      trust: this.trust,
      issuerList: 'TL-PID',
      nonce: tx.nonce,
      skewSeconds: SKEW,
      requireStatus: true,
      maxStatusListBytes: MAX_STATUS_LIST_BYTES,
      trustedAuthorities: credentialQuery.trusted_authorities,
      mode,
    };
    const credential = !presented
      ? undefined
      : forged.format === 'mso_mdoc'
        ? await validateMdocPresentation(presented, {
            ...common,
            expectedDocType: PID_DOCTYPE,
            handover,
            jwkThumbprint: await jwkThumbprint(tx.key.publicJwk as JsonWebKey),
            fetchStatusList: fetchList,
            fetchIdentifierList: fetchList,
          })
        : await validateSdJwtVcPresentation(presented, {
            ...common,
            expectedVct: [PID_VCT],
            audience,
            kbMaxAgeSeconds: KB_MAX_AGE,
            fetchStatusList: fetchList,
          });
    return { forged, response: response.checks, credential, failures: [...response.failures, ...(credential?.failures ?? [])] };
  }
}
