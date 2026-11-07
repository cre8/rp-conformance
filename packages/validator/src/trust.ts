import { verifyCompact } from '@owf/eudi-jades';
import { LoTEProfile, validateLoTEProfile } from '@owf/eudi-lote';
import { type Certificate, parseCertificate } from '@owf/x509';
import { base64url, verifyEs256 } from '@rp-conformance/forge';
import { validatePath } from './x509-path';

export interface TrustedService {
  type: string;
  anchors: Certificate[];
}

export interface TrustedEntity {
  name: string;
  services: TrustedService[];
}

export interface LoadedList {
  id: string;
  loteType: string;
  sequenceNumber: number;
  nextUpdate: Date;
  entities: TrustedEntity[];
}

/** How a Relying Party is configured for one list: where it is and which scheme operator certificate seals it. */
export interface ListSource {
  id: string;
  url: string;
  loteType: string;
  schemeOperatorCertificatePem: string;
}

const PROFILE_BY_TYPE: Record<string, LoTEProfile> = {
  'http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList': LoTEProfile.EUPIDProvidersList,
  'http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList': LoTEProfile.EUPubEAAProvidersList,
  'http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList': LoTEProfile.EUWalletProvidersList,
  'http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList': LoTEProfile.EUWRPACProvidersList,
  'http://uri.etsi.org/19602/LoTEType/EUWRPRCProvidersList': LoTEProfile.EUWRPRCProvidersList,
};

export class TrustListError extends Error {}

/**
 * Verifies a sealed LoTE as a Relying Party must: the JAdES signature with the configured scheme operator certificate
 * (any `x5c` must be that certificate), the profile of its `LoTEType` (ETSI TS 119 602, strict), and `NextUpdate`.
 */
export async function verifyLote(jws: string, source: ListSource, now = new Date()): Promise<LoadedList> {
  const operator = parseCertificate(source.schemeOperatorCertificatePem);
  const header = base64url.decodeJson<{ x5c?: string[] }>(jws.split('.')[0] ?? '');
  if (header.x5c && Buffer.from(header.x5c[0] ?? '', 'base64').compare(Buffer.from(operator.der)) !== 0) {
    throw new TrustListError(`${source.id}: sealed by a certificate other than the scheme operator certificate`);
  }
  const jwk = operator.publicKey.jwk;
  if (!jwk) throw new TrustListError(`${source.id}: scheme operator key is not supported`);
  const result = await verifyCompact(jws, (data, signature) => verifyEs256(jwk, data, base64url.decode(signature)));
  if (!result.valid) throw new TrustListError(`${source.id}: seal does not verify`);
  const profile = PROFILE_BY_TYPE[source.loteType];
  if (!profile) throw new TrustListError(`${source.id}: unsupported LoTEType ${source.loteType}`);
  const validation = validateLoTEProfile(result.payload, profile);
  if (!validation.valid) {
    throw new TrustListError(`${source.id}: not a valid ${profile}: ${validation.issues.map((i) => i.message).join('; ')}`);
  }
  const lote = (result.payload as { LoTE: Record<string, any> }).LoTE;
  const info = lote.ListAndSchemeInformation;
  const nextUpdate = new Date(info.NextUpdate);
  if (nextUpdate < now) throw new TrustListError(`${source.id}: NextUpdate ${info.NextUpdate} has passed`);
  const entities: TrustedEntity[] = (lote.TrustedEntitiesList ?? []).map((entity: any) => ({
    name: entity.TrustedEntityInformation.TEName[0].value,
    services: entity.TrustedEntityServices.map((svc: any) => ({
      type: svc.ServiceInformation.ServiceTypeIdentifier,
      anchors: (svc.ServiceInformation.ServiceDigitalIdentity?.X509Certificates ?? []).map((c: { val: string }) => parseCertificate(c.val)),
    })),
  }));
  return { id: source.id, loteType: info.LoTEType, sequenceNumber: info.LoTESequenceNumber, nextUpdate, entities };
}

export type TrustMatch = { ok: true; entity: TrustedEntity; anchor: Certificate; leaf: Certificate } | { ok: false; reason: string };

/** The trust configuration of a Relying Party, derived from the lists of `default_trust_configuration_rp`. */
export class TrustStore {
  readonly lists = new Map<string, LoadedList>();
  /** Every retrieval, for evidence. */
  readonly retrievals: { id: string; url: string; at: string; status: number }[] = [];

  constructor(
    private readonly sources: ListSource[],
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  /** Fetches and verifies every configured list. A list that fails is left out, so nothing it lists is trusted. */
  async refresh(now = new Date()): Promise<{ id: string; error?: string }[]> {
    const results: { id: string; error?: string }[] = [];
    for (const source of this.sources) {
      try {
        const response = await this.fetchImpl(source.url);
        this.retrievals.push({ id: source.id, url: source.url, at: new Date().toISOString(), status: response.status });
        if (!response.ok) throw new TrustListError(`${source.id}: HTTP ${response.status}`);
        this.lists.set(source.id, await verifyLote((await response.text()).trim(), source, now));
        results.push({ id: source.id });
      } catch (error) {
        this.lists.delete(source.id);
        results.push({ id: source.id, error: (error as Error).message });
      }
    }
    return results;
  }

  /**
   * Finds the entity of a list whose service of the given type (suffix, for example `/Issuance`) has an anchor the
   * `x5c` chain validates to.
   */
  async match(listId: string, serviceTypeSuffix: string, x5c: string[], now = new Date()): Promise<TrustMatch> {
    const list = this.lists.get(listId);
    if (!list) return { ok: false, reason: `${listId} is not available` };
    const reasons: string[] = [];
    for (const entity of list.entities) {
      const anchors = entity.services.filter((s) => s.type.endsWith(serviceTypeSuffix)).flatMap((s) => s.anchors);
      if (anchors.length === 0) continue;
      const path = await validatePath(x5c, anchors, now);
      if (path.ok) return { ok: true, entity, anchor: path.anchor, leaf: path.leaf };
      reasons.push(`${entity.name}: ${path.reason}`);
    }
    return { ok: false, reason: `no ${serviceTypeSuffix} anchor of ${listId} validates the chain (${reasons.join('; ') || 'no candidates'})` };
  }

  /**
   * The anchors trusted for status lists of a credential whose issuer matched `entity`: the anchors under the revocation
   * service of the same entity in the same list (FCAF defaults, `default_trust_configuration_rp`).
   */
  revocationAnchors(entity: TrustedEntity): Certificate[] {
    return entity.services.filter((s) => s.type.endsWith('/Revocation')).flatMap((s) => s.anchors);
  }
}
