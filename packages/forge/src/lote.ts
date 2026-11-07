import { createLoTE, LOTE_TYPES, LoTEProfile, service, trustedEntity } from '@owf/eudi-lote';
import { Token } from '@owf/eudi-jades';
import { base64url, signEs256 } from './crypto';
import type { CertifiedKey, LoteListId, TestEntity, TestPki } from './pki';

const MONTH = 30 * 24 * 60 * 60 * 1000;

interface ListProfile {
  loteType: string;
  /** The `@owf/eudi-lote` profile the list is validated against. */
  profile: LoTEProfile;
  schemeName: string;
  statusDeterminationApproach: string;
  schemeTypeCommunityRules: string;
  issuanceServiceType: string;
  revocationServiceType: string;
  informationUriPrefix: string;
  /** ETSI TS 119 602 H: Pub-EAA lists carry `HistoricalInformationPeriod` and a service status. */
  pubEaa?: boolean;
}

/** ETSI TS 119 602 Annexes D to H, as `@owf/eudi-lote` validates them in `strict` mode. */
export const LIST_PROFILES: Record<LoteListId, ListProfile> = {
  'TL-PID': {
    loteType: LOTE_TYPES.EUPIDProvidersList,
    profile: LoTEProfile.EUPIDProvidersList,
    schemeName: 'Test PID Providers list',
    statusDeterminationApproach: 'http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU',
    schemeTypeCommunityRules: 'http://uri.etsi.org/19602/PIDProviders/schemerules/EU',
    issuanceServiceType: 'http://uri.etsi.org/19602/SvcType/PID/Issuance',
    revocationServiceType: 'http://uri.etsi.org/19602/SvcType/PID/Revocation',
    informationUriPrefix: 'http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/',
  },
  'TL-PUB': {
    loteType: LOTE_TYPES.EUPubEAAProvidersList,
    profile: LoTEProfile.EUPubEAAProvidersList,
    schemeName: 'Test Pub-EAA Providers list',
    statusDeterminationApproach: 'http://uri.etsi.org/19602/PubEAAProvidersList/StatusDetn/EU',
    schemeTypeCommunityRules: 'http://uri.etsi.org/19602/PubEAAProvidersList/schemerules/EU',
    issuanceServiceType: 'http://uri.etsi.org/19602/SvcType/PubEAA/Issuance',
    revocationServiceType: 'http://uri.etsi.org/19602/SvcType/PubEAA/Revocation',
    informationUriPrefix: 'http://uri.etsi.org/19602/ListOfTrustedEntities/PubEAAProvider/',
    pubEaa: true,
  },
  'TL-WP': {
    loteType: LOTE_TYPES.EUWalletProvidersList,
    profile: LoTEProfile.EUWalletProvidersList,
    schemeName: 'Test Wallet Providers list',
    statusDeterminationApproach: 'http://uri.etsi.org/19602/WalletProvidersList/StatusDetn/EU',
    schemeTypeCommunityRules: 'http://uri.etsi.org/19602/WalletProvidersList/schemerules/EU',
    issuanceServiceType: 'http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance',
    revocationServiceType: 'http://uri.etsi.org/19602/SvcType/WalletSolution/Revocation',
    informationUriPrefix: 'http://uri.etsi.org/19602/ListOfTrustedEntities/WalletProvider/',
  },
  'TL-AC': {
    loteType: LOTE_TYPES.EUWRPACProvidersList,
    profile: LoTEProfile.EUWRPACProvidersList,
    schemeName: 'Test Access Certificate Authorities list',
    statusDeterminationApproach: 'http://uri.etsi.org/19602/WRPACProvidersList/StatusDetn/EU',
    schemeTypeCommunityRules: 'http://uri.etsi.org/19602/WRPACProvidersList/schemerules/EU',
    issuanceServiceType: 'http://uri.etsi.org/19602/SvcType/WRPAC/Issuance',
    revocationServiceType: 'http://uri.etsi.org/19602/SvcType/WRPAC/Revocation',
    informationUriPrefix: 'http://uri.etsi.org/19602/ListOfTrustedEntities/WRPACProvider/',
  },
  'TL-RC': {
    loteType: LOTE_TYPES.EUWRPRCProvidersList,
    profile: LoTEProfile.EUWRPRCProvidersList,
    schemeName: 'Test Providers of registration certificates list',
    // Sic: ETSI TS 119 602 I.3 spells it "WRPRCrovidersList"; @owf/eudi-lote follows the text.
    statusDeterminationApproach: 'http://uri.etsi.org/19602/WRPRCrovidersList/StatusDetn/EU',
    schemeTypeCommunityRules: 'http://uri.etsi.org/19602/WRPRCProvidersList/schemerules/EU',
    issuanceServiceType: 'http://uri.etsi.org/19602/SvcType/WRPRC/Issuance',
    revocationServiceType: 'http://uri.etsi.org/19602/SvcType/WRPRC/Revocation',
    informationUriPrefix: 'http://uri.etsi.org/19602/ListOfTrustedEntities/WRPRCProvider/',
  },
};

const PUB_EAA_NOTIFIED = 'http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified';

const der = (key: CertifiedKey) => Buffer.from(key.certificate.der).toString('base64');

function buildEntity(entity: TestEntity, profile: ListProfile) {
  const informationUri = `${profile.informationUriPrefix}DE`;
  const builder = trustedEntity()
    .name(entity.spec.id)
    .postalAddress({ StreetAddress: 'Teststrasse 1', Locality: 'Berlin', PostalCode: '10115', Country: 'DE' })
    .email(`trust@${entity.spec.host}`)
    .infoUri(informationUri);
  const services: [string, CertifiedKey][] = [
    [profile.issuanceServiceType, entity.anchors.issuance],
    [profile.revocationServiceType, entity.anchors.revocation],
  ];
  for (const [type, anchor] of services) {
    const svc = service().name(`${entity.spec.id} ${type.split('/').pop()}`).type(type).addCertificate(der(anchor));
    if (profile.pubEaa) svc.status(PUB_EAA_NOTIFIED);
    builder.addService(svc.build());
  }
  return builder.build();
}

export interface LoteBuildOptions {
  list: LoteListId;
  pki: TestPki;
  /** Entity IDs on the list; default: every entity of `default_trust_configuration_rp` for this list. */
  entities?: string[];
  sequenceNumber?: number;
  now?: Date;
  /** Where the list is published (`DistributionPoints`). */
  distributionPoint?: string;
}

/** The entities of `default_trust_configuration_rp` that are on a list. */
export function defaultEntitiesOf(pki: TestPki, list: LoteListId): string[] {
  return Object.values(pki.entities)
    // PP-W ("all services withdrawn") needs a representation of withdrawal in a PID Providers list, which
    // TS 119 602 D does not give a ServiceStatus for. It is left off until the TrustMechanisms test cases define it.
    .filter((entity) => entity.spec.list === list && !entity.spec.withdrawn)
    .map((entity) => entity.spec.id);
}

/** Builds the LoTE document (ETSI TS 119 602, JSON) of a test list. */
export function buildLoteDocument(options: LoteBuildOptions) {
  const profile = LIST_PROFILES[options.list];
  const now = options.now ?? new Date();
  const ids = options.entities ?? defaultEntitiesOf(options.pki, options.list);
  return createLoTE(
    {
      LoTEVersionIdentifier: 1,
      LoTESequenceNumber: options.sequenceNumber ?? 1,
      LoTEType: profile.loteType,
      SchemeOperatorName: [{ lang: 'en', value: `${options.list} scheme operator` }],
      SchemeOperatorAddress: {
        SchemeOperatorPostalAddress: [
          { lang: 'en', StreetAddress: 'Teststrasse 1', Locality: 'Berlin', PostalCode: '10115', Country: 'DE' },
        ],
        SchemeOperatorElectronicAddress: [{ lang: 'en', uriValue: 'mailto:operator@trust.rp-test' }],
      },
      SchemeName: [{ lang: 'en', value: profile.schemeName }],
      SchemeInformationURI: [{ lang: 'en', uriValue: 'https://trust.rp-test/scheme' }],
      StatusDeterminationApproach: profile.statusDeterminationApproach,
      SchemeTypeCommunityRules: [{ lang: 'en', uriValue: profile.schemeTypeCommunityRules }],
      SchemeTerritory: 'EU',
      PolicyOrLegalNotice: [{ LoTELegalNotice: 'Test list of the RP conformance harness. Not for production use.', lang: 'en' }],
      ...(profile.pubEaa ? { HistoricalInformationPeriod: 65535 } : {}),
      ListIssueDateTime: now.toISOString(),
      NextUpdate: new Date(now.getTime() + MONTH).toISOString(),
      ...(options.distributionPoint ? { DistributionPoints: [options.distributionPoint] } : {}),
    } as never,
    ids.map((id) => buildEntity(options.pki.entities[id], profile)),
  );
}

/**
 * Seals a LoTE document as a JAdES B-B signature in compact serialisation (ETSI TS 119 182-1): ES256,
 * the scheme operator certificate in `x5c`, and `iat` as the claimed signing time.
 */
export async function sealLote(document: unknown, operator: CertifiedKey, now = new Date()): Promise<string> {
  const token = new Token(document as Record<string, unknown>)
    .setProtectedHeader({ alg: 'ES256', typ: 'trustlist+jwt' })
    .setX5c([der(operator)])
    .setSigningTime(now);
  await token.sign(async (signingInput: string) => base64url.encode(await signEs256(operator.key.privateKey, signingInput)));
  return token.toString();
}

/** Builds and seals a test list. */
export async function buildSealedLote(options: LoteBuildOptions): Promise<{ jws: string; document: unknown }> {
  const document = buildLoteDocument(options);
  const jws = await sealLote(document, options.pki.schemeOperators[options.list], options.now);
  return { jws, document };
}
