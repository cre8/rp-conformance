// `TL-WP` as the issuer suite needs it (issuer catalogue section 3.2): which service of a Wallet Provider anchors which
// artifact, its versions, and publishing them through the Test Trust Infrastructure.
import { buildSealedLote, type CertifiedKey, defaultEntitiesOf, LIST_PROFILES, type TestEntity, type TestPki } from '@eudi-pcaf/forge';
import type { TrustInfrastructure } from '@eudi-pcaf/trust-infrastructure';

/** What a Wallet Provider signs: WIAs, KAs, or the status lists of both. */
export type WalletProviderPurpose = 'wia' | 'ka' | 'status';

/** The Wallet Providers of the issuer suite: granted (`WP-A`, `WP-B`), withdrawn (`WP-W`), listed later (`WP-C`). */
export const WALLET_PROVIDER_IDS = ['WP-A', 'WP-B', 'WP-W', 'WP-C'] as const;
export type WalletProviderEntityId = (typeof WALLET_PROVIDER_IDS)[number];

/** The version of `TL-WP` from which `WP-C` is listed (PP_Inf_003). */
export const TL_WP_VERSION_WITH_WP_C = 2;

const profile = LIST_PROFILES['TL-WP'];

const solutionOf = (entity: TestEntity) => {
  if (!entity.spec.walletSolution) throw new Error(`${entity.spec.id} is not a Wallet Provider`);
  return entity.spec.walletSolution;
};

/** The service of `TL-WP` whose anchor a relying issuer must use for a purpose: its type, ServiceName and anchor. */
export function serviceFor(entity: TestEntity, purpose: WalletProviderPurpose): { type: string; name: string; anchor: CertifiedKey } {
  const solution = solutionOf(entity);
  switch (purpose) {
    case 'wia':
      return { type: profile.issuanceServiceType, name: solution.name, anchor: entity.anchors.issuance };
    case 'ka':
      return entity.keyAttestation && solution.keyAttestationService
        ? { type: profile.issuanceServiceType, name: solution.keyAttestationService, anchor: entity.keyAttestation.anchor }
        : { type: profile.issuanceServiceType, name: solution.name, anchor: entity.anchors.issuance };
    case 'status':
      return { type: profile.revocationServiceType, name: `${entity.spec.id} ${profile.revocationServiceType.split('/').pop()}`, anchor: entity.anchors.revocation };
  }
}

/** The signing certificate a Wallet Provider uses for a purpose, under the anchor of `serviceFor`. */
export function signerFor(entity: TestEntity, purpose: WalletProviderPurpose): CertifiedKey {
  solutionOf(entity);
  if (purpose === 'ka') return entity.keyAttestation?.signer ?? entity.signers.issuance;
  return purpose === 'status' ? entity.signers.revocation : entity.signers.issuance;
}

/** The entities of a version of `TL-WP`: `WP-A`, `WP-B` and `WP-W`, and from version 2 also `WP-C`. */
export function tlWpEntities(pki: TestPki, sequenceNumber = 1): string[] {
  const entities = defaultEntitiesOf(pki, 'TL-WP');
  return sequenceNumber >= TL_WP_VERSION_WITH_WP_C ? [...entities, 'WP-C'] : entities;
}

export interface TlWpOptions {
  sequenceNumber?: number;
  /** Entities instead of those of `tlWpEntities`. */
  entities?: string[];
  distributionPoint?: string;
  now?: Date;
}

/** Builds and seals a version of `TL-WP`. */
export async function buildTlWp(pki: TestPki, options: TlWpOptions = {}) {
  const sequenceNumber = options.sequenceNumber ?? 1;
  return buildSealedLote({
    list: 'TL-WP',
    pki,
    entities: options.entities ?? tlWpEntities(pki, sequenceNumber),
    sequenceNumber,
    ...(options.distributionPoint ? { distributionPoint: options.distributionPoint } : {}),
    ...(options.now ? { now: options.now } : {}),
  });
}

/** Builds, seals and publishes a version of `TL-WP` at `<base>/<namespace>/TL-WP`. */
export async function publishTlWp(trust: TrustInfrastructure, namespace: string, pki: TestPki, options: TlWpOptions = {}) {
  const sealed = await buildTlWp(pki, { distributionPoint: trust.urlOf(namespace, 'TL-WP'), ...options });
  const { url, version } = trust.publish(namespace, 'TL-WP', sealed.jws);
  return { url, version, ...sealed };
}

interface LoteDocument {
  LoTE: {
    TrustedEntitiesList?: {
      TrustedEntityInformation: { TEName: { value: string }[] };
      TrustedEntityServices: { ServiceInformation: { ServiceTypeIdentifier: string; ServiceName: { value: string }[]; ServiceDigitalIdentity?: { X509Certificates?: { val: string }[] } } }[];
    }[];
  };
}

/**
 * The anchors (base64 DER) a LoTE document publishes for one service of one entity, matched by entity name, service type
 * and ServiceName: what an issuer reads from `TL-WP` to validate a WIA, KA or status list of that Wallet Provider.
 */
export function anchorsInList(document: unknown, query: { entity: string; type: string; name: string }): string[] {
  const entities = (document as LoteDocument).LoTE.TrustedEntitiesList ?? [];
  return entities
    .filter((entity) => entity.TrustedEntityInformation.TEName.some((name) => name.value === query.entity))
    .flatMap((entity) => entity.TrustedEntityServices)
    .filter(({ ServiceInformation: info }) => info.ServiceTypeIdentifier === query.type && info.ServiceName.some((name) => name.value === query.name))
    .flatMap(({ ServiceInformation: info }) => (info.ServiceDigitalIdentity?.X509Certificates ?? []).map((certificate) => certificate.val));
}
