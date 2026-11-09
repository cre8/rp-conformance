// The self-validation fixture (harness design section 7): the test PKI and lists of `default_trust_configuration_rp`
// served from memory, and one function that builds a presentation step exactly as the controller does (forge, fault
// layer, Conformance Wallet response) and runs the reference validator over it in `all` mode.
import { randomUUID } from 'node:crypto';
import type { DcqlQuery, DefaultQueryId, PresentationAction } from '@rp-conformance/core';
import {
  buildAuthorizationResponse,
  buildSealedLote,
  createTestPki,
  defaultEntitiesOf,
  defaultQueries,
  type EcKeyPair,
  forgePresentation,
  type ForgedCredential,
  generateEcKeyPair,
  LIST_PROFILES,
  type LoteListId,
  PID_VCT,
  presentSdJwtVc,
  type ServedStatusList,
  type TestPki,
} from '@rp-conformance/forge';
import { exportJWK, generateKeyPair, type JWK } from 'jose';
import type { CheckResult } from '@rp-conformance/core';
import { type SdJwtVcValidation, TrustStore, type ValidationMode, validateAuthorizationResponse, validateSdJwtVcPresentation } from '../src/index';

export const LISTS: LoteListId[] = ['TL-PID', 'TL-PUB', 'TL-WP', 'TL-AC', 'TL-RC'];
export const AUDIENCE = 'x509_hash:self-validation';
export const SKEW = 60;
export const KB_MAX_AGE = 300;
export const MAX_STATUS_LIST_BYTES = 1 << 20;
const BASE = 'https://trust.rp-test/self-validation';

export interface Transaction {
  key: { kid: string; privateKey: CryptoKey; publicJwk: JWK };
  nonce: string;
  state: string;
}

export interface SelfValidation {
  forged: ForgedCredential;
  response: CheckResult[];
  credential?: SdJwtVcValidation;
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

  /** Builds a presentation step and validates it in `all` mode, like the reference Relying Party but without stopping. */
  async validate(action: PresentationAction, options: { mode?: ValidationMode; other?: Transaction } = {}): Promise<SelfValidation> {
    const mode = options.mode ?? 'all';
    const forged = await forgePresentation(action, {
      pki: this.pki,
      holderPublicJwk: this.holder.publicJwk,
      allocateStatusUri: () => `https://status.rp-test/self-validation/${randomUUID()}`,
      skewSeconds: SKEW,
    });
    if (forged.statusList) this.statusLists.set(forged.statusList.uri, forged.statusList.served);
    const tx = await this.transaction();
    const query = this.queries[action.query];
    const credentialQuery = query.credentials[0];
    const presentation = await presentSdJwtVc(forged.compact, {
      holderPrivateKey: this.holder.privateKey,
      disclose: (credentialQuery.claims ?? []).map((c) => String(c.path[0])),
      audience: AUDIENCE,
      nonce: tx.nonce,
    });
    const encValues = ['A128GCM', 'A256GCM'];
    const form = await buildAuthorizationResponse(
      {
        payload: { vp_token: { [credentialQuery.id]: [presentation] }, state: tx.state },
        recipient: tx.key.publicJwk,
        enc: action.response.enc ?? 'A128GCM',
        walletKey: this.walletKey,
        otherTransactionKey: options.other?.key.publicJwk,
      },
      action.response.faults[0],
    );
    const response = await validateAuthorizationResponse(form, { keys: [tx.key], encValues, state: tx.state, mode });
    const presented = (response.payload?.vp_token as Record<string, string[]> | undefined)?.[credentialQuery.id]?.[0];
    const credential = presented
      ? await validateSdJwtVcPresentation(presented, {
          trust: this.trust,
          issuerList: 'TL-PID',
          expectedVct: [PID_VCT],
          nonce: tx.nonce,
          audience: AUDIENCE,
          skewSeconds: SKEW,
          kbMaxAgeSeconds: KB_MAX_AGE,
          requireStatus: true,
          maxStatusListBytes: MAX_STATUS_LIST_BYTES,
          trustedAuthorities: credentialQuery.trusted_authorities,
          fetchStatusList: async (uri) => {
            const served = this.statusLists.get(uri);
            return served ? { status: 200, body: served.body, contentType: served.contentType } : { status: 404, body: '' };
          },
          mode,
        })
      : undefined;
    return { forged, response: response.checks, credential, failures: [...response.failures, ...(credential?.failures ?? [])] };
  }
}
