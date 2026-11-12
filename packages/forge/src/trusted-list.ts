// The lists of `default_trust_configuration_rp` in ETSI TS 119 612 (V2.4.1) format: the test list of trusted lists
// (LOTL) and the test Trusted List `TL-QEAA` it points to, with the QTSPs `QP-A`, `QP-N` and `QP-W`. `@owf/eudi-tl` only
// parses and verifies Trusted Lists, so the lists are built here as XML and signed with xadesjs: an enveloped XAdES-B-B
// signature (ETSI EN 319 132-1) with the constraints of TS 119 612 Annex B.
import { randomUUID } from 'node:crypto';
import { DOMImplementation, DOMParser, XMLSerializer } from '@xmldom/xmldom';
import * as xadesjs from 'xadesjs';
import * as xpath from 'xpath';
import { type CertifiedKey, type TestEntity, type TestPki, TRUSTED_LIST_OPERATORS, type TrustedListId } from './pki';

const DAY = 24 * 60 * 60 * 1000;

/** Namespaces of TS 119 612 Annex B and C. */
export const TSL_NAMESPACE = 'http://uri.etsi.org/02231/v2#';
const TSLX_NAMESPACE = 'http://uri.etsi.org/02231/v2/additionaltypes#';

/** `TSLTag` (clause 5.2.1, D.1). */
export const TSL_TAG = 'http://uri.etsi.org/19612/TSLTag';
/** Media type of a Trusted List (clause 6.2.1.1). */
export const TRUSTED_LIST_MEDIA_TYPE = 'application/vnd.etsi.tsl+xml';

/** `TSLType` of a Member State list and of the list of trusted lists (clause 5.3.3, D.5.1). */
export const TSL_TYPE = {
  EUgeneric: 'http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric',
  EUlistofthelists: 'http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists',
} as const;

/** Service types for the issuance of attestations of attributes (clause 5.5.1.1 k, 5.5.1.2 n). */
export const EAA_SERVICE_TYPE = {
  /** Issuance of qualified electronic attestations of attributes by a QTSP. */
  qualified: 'http://uri.etsi.org/TrstSvc/Svctype/EAA/Q',
  /** Issuance of not qualified electronic attestations of attributes. */
  notQualified: 'http://uri.etsi.org/TrstSvc/Svctype/EAA',
} as const;

/** Service statuses (clause 5.5.4): granted or withdrawn for a qualified service, recognised at national level otherwise. */
export const SERVICE_STATUS = {
  granted: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
  withdrawn: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn',
  recognisedAtNationalLevel: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel',
} as const;

const STATUS_DETERMINATION = 'http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUappropriate';
const SCHEME_RULES = {
  common: 'http://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUcommon',
  listOfTheLists: 'http://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUlistofthelists',
  territory: (territory: string) => `http://uri.etsi.org/TrstSvc/TrustedList/schemerules/${territory}`,
};

const escape = (value: string) =>
  value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
/** Date-time in UTC without fractions (clause 5.1.3). */
const dateTime = (date: Date) => `${date.toISOString().slice(0, 19)}Z`;
const base64Der = (key: CertifiedKey) => Buffer.from(key.certificate.der).toString('base64');
const name = (tag: string, value: string) => `<${tag}><Name xml:lang="en">${escape(value)}</Name></${tag}>`;
const uris = (tag: string, values: string[]) => `<${tag}>${values.map((v) => `<URI xml:lang="en">${escape(v)}</URI>`).join('')}</${tag}>`;

const address = (tag: string, host: string, territory: string) =>
  `<${tag}><PostalAddresses><PostalAddress xml:lang="en"><StreetAddress>Teststrasse 1</StreetAddress><Locality>Berlin</Locality>` +
  `<PostalCode>10115</PostalCode><CountryName>${territory}</CountryName></PostalAddress></PostalAddresses>` +
  `<ElectronicAddress><URI xml:lang="en">mailto:trust@${escape(host)}</URI><URI xml:lang="en">https://${escape(host)}/</URI></ElectronicAddress></${tag}>`;

/** A `ServiceDigitalIdentity` (clause 5.5.3): the certificate, its subject name and its subject key identifier. */
function digitalIdentity(key: CertifiedKey): string {
  const { certificate } = key;
  const ski = certificate.subjectKeyIdentifier ? Buffer.from(certificate.subjectKeyIdentifier, 'hex').toString('base64') : undefined;
  return (
    `<ServiceDigitalIdentity><DigitalId><X509Certificate>${base64Der(key)}</X509Certificate></DigitalId>` +
    `<DigitalId><X509SubjectName>${escape(certificate.subject.rfc4514)}</X509SubjectName></DigitalId>` +
    (ski ? `<DigitalId><X509SKI>${ski}</X509SKI></DigitalId>` : '') +
    '</ServiceDigitalIdentity>'
  );
}

export interface TrustedListPointer {
  list: TrustedListId;
  location: string;
  /** The certificate(s) the pointed-to list is signed with. */
  signers: CertifiedKey[];
}

/** An `OtherTSLPointer` (clause 5.3.13) with the qualifiers a Member State list and the LOTL carry. */
function pointer(target: TrustedListPointer): string {
  const operator = TRUSTED_LIST_OPERATORS[target.list];
  const lotl = target.list === 'LOTL';
  const rules = lotl ? [SCHEME_RULES.listOfTheLists] : [SCHEME_RULES.common, SCHEME_RULES.territory(operator.territory)];
  return (
    '<OtherTSLPointer><ServiceDigitalIdentities>' +
    target.signers.map((signer) => `<ServiceDigitalIdentity><DigitalId><X509Certificate>${base64Der(signer)}</X509Certificate></DigitalId></ServiceDigitalIdentity>`).join('') +
    `</ServiceDigitalIdentities><TSLLocation>${escape(target.location)}</TSLLocation><AdditionalInformation>` +
    `<OtherInformation><TSLType>${lotl ? TSL_TYPE.EUlistofthelists : TSL_TYPE.EUgeneric}</TSLType></OtherInformation>` +
    `<OtherInformation>${name('SchemeOperatorName', operator.name)}</OtherInformation>` +
    `<OtherInformation>${uris('SchemeTypeCommunityRules', rules)}</OtherInformation>` +
    `<OtherInformation><SchemeTerritory>${operator.territory}</SchemeTerritory></OtherInformation>` +
    `<OtherInformation><tslx:MimeType>${TRUSTED_LIST_MEDIA_TYPE}</tslx:MimeType></OtherInformation>` +
    '</AdditionalInformation></OtherTSLPointer>'
  );
}

/**
 * The service of a QTSP in `TL-QEAA` (clause 5.5): `QP-A` a granted qualified service for the issuance of QEAAs,
 * `QP-N` a service for the issuance of attestations that is not qualified (recognised at national level), `QP-W` a
 * qualified service withdrawn ten days ago, with its granted status in the service history. The current status starts
 * before the attestations the harness issues (an mdoc is signed two days in the past).
 */
function qeaaService(entity: TestEntity, now: Date): string {
  const service = entity.spec.qeaaService ?? 'granted';
  const anchor = entity.anchors.issuance;
  const since = new Date(now.getTime() - 30 * DAY);
  const type = service === 'not-qualified' ? EAA_SERVICE_TYPE.notQualified : EAA_SERVICE_TYPE.qualified;
  const serviceName = `${entity.spec.id} ${service === 'not-qualified' ? 'issuance of electronic attestations of attributes' : 'issuance of qualified electronic attestations of attributes'}`;
  const status =
    service === 'withdrawn' ? SERVICE_STATUS.withdrawn : service === 'not-qualified' ? SERVICE_STATUS.recognisedAtNationalLevel : SERVICE_STATUS.granted;
  const statusSince = service === 'withdrawn' ? new Date(now.getTime() - 10 * DAY) : since;
  const history =
    service === 'withdrawn'
      ? `<ServiceHistory><ServiceHistoryInstance><ServiceTypeIdentifier>${type}</ServiceTypeIdentifier>${name('ServiceName', serviceName)}` +
        `${digitalIdentity(anchor)}<ServiceStatus>${SERVICE_STATUS.granted}</ServiceStatus><StatusStartingTime>${dateTime(since)}</StatusStartingTime>` +
        '</ServiceHistoryInstance></ServiceHistory>'
      : '';
  return (
    `<TSPService><ServiceInformation><ServiceTypeIdentifier>${type}</ServiceTypeIdentifier>${name('ServiceName', serviceName)}` +
    `${digitalIdentity(anchor)}<ServiceStatus>${status}</ServiceStatus><StatusStartingTime>${dateTime(statusSince)}</StatusStartingTime>` +
    `</ServiceInformation>${history}</TSPService>`
  );
}

/** A `TrustServiceProvider` (clause 5.4). */
function provider(entity: TestEntity, index: number, now: Date): string {
  const territory = TRUSTED_LIST_OPERATORS['TL-QEAA'].territory;
  return (
    `<TrustServiceProvider><TSPInformation>${name('TSPName', entity.spec.id)}` +
    // The trade name carries an official registration identifier (clause 5.4.2); these are made up for the test.
    `${name('TSPTradeName', `VAT${territory}-${String(100000001 + index)}`)}${address('TSPAddress', entity.spec.host, territory)}` +
    `${uris('TSPInformationURI', [`https://${entity.spec.host}/`])}</TSPInformation>` +
    `<TSPServices>${qeaaService(entity, now)}</TSPServices></TrustServiceProvider>`
  );
}

export interface TrustedListBuildOptions {
  list: TrustedListId;
  pki: TestPki;
  /** Where the list is published (`DistributionPoints`). */
  location: string;
  /** The pointers of the list: from `TL-QEAA` to the LOTL, from the LOTL to `TL-QEAA` and to itself. */
  pointers: TrustedListPointer[];
  /** For `TL-QEAA`: the QTSPs on the list; default every entity of `default_trust_configuration_rp` on it. */
  entities?: string[];
  sequenceNumber?: number;
  now?: Date;
}

/** The entities of `default_trust_configuration_rp` on `TL-QEAA`. */
export const trustedListEntitiesOf = (pki: TestPki): string[] =>
  Object.values(pki.entities)
    .filter((entity) => entity.spec.trustedList === 'TL-QEAA')
    .map((entity) => entity.spec.id);

/**
 * Builds a list in ETSI TS 119 612 V2.4.1 format, unsigned: `TL-QEAA` as a Member State list (`EUgeneric`) with its
 * QTSPs, or the LOTL (`EUlistofthelists`), which carries pointers only. Both list the mandatory scheme information of
 * an EU list, including the pointers (clause 5.3.13) and a `NextUpdate` one month ahead (at most six months).
 */
export function buildTrustedListXml(options: TrustedListBuildOptions): string {
  const now = options.now ?? new Date();
  const lotl = options.list === 'LOTL';
  const operator = TRUSTED_LIST_OPERATORS[options.list];
  const entities = lotl ? [] : (options.entities ?? trustedListEntitiesOf(options.pki));
  const rules = lotl ? [SCHEME_RULES.listOfTheLists] : [SCHEME_RULES.common, SCHEME_RULES.territory(operator.territory)];
  const schemeName = lotl
    ? 'EU:Test list of trusted lists of the RP conformance harness, not for production use'
    : `${operator.territory}:Test trusted list ${options.list} of the RP conformance harness, not for production use`;
  return (
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    `<TrustServiceStatusList xmlns="${TSL_NAMESPACE}" xmlns:tslx="${TSLX_NAMESPACE}" TSLTag="${TSL_TAG}" Id="tsl-${randomUUID()}">` +
    '<SchemeInformation><TSLVersionIdentifier>6</TSLVersionIdentifier>' +
    `<TSLSequenceNumber>${options.sequenceNumber ?? 1}</TSLSequenceNumber><TSLType>${lotl ? TSL_TYPE.EUlistofthelists : TSL_TYPE.EUgeneric}</TSLType>` +
    `${name('SchemeOperatorName', operator.name)}${address('SchemeOperatorAddress', 'trust.rp-test', operator.territory)}` +
    `${name('SchemeName', schemeName)}${uris('SchemeInformationURI', ['https://trust.rp-test/scheme'])}` +
    `<StatusDeterminationApproach>${STATUS_DETERMINATION}</StatusDeterminationApproach>${uris('SchemeTypeCommunityRules', rules)}` +
    `<SchemeTerritory>${operator.territory}</SchemeTerritory>` +
    '<PolicyOrLegalNotice><TSLLegalNotice xml:lang="en">Test list of the RP conformance harness. Not for production use.</TSLLegalNotice></PolicyOrLegalNotice>' +
    '<HistoricalInformationPeriod>65535</HistoricalInformationPeriod>' +
    `<PointersToOtherTSL>${options.pointers.map(pointer).join('')}</PointersToOtherTSL>` +
    `<ListIssueDateTime>${dateTime(now)}</ListIssueDateTime><NextUpdate><dateTime>${dateTime(new Date(now.getTime() + 30 * DAY))}</dateTime></NextUpdate>` +
    `<DistributionPoints><URI>${escape(options.location)}</URI></DistributionPoints></SchemeInformation>` +
    (entities.length
      ? `<TrustServiceProviderList>${entities.map((id, i) => provider(options.pki.entities[id], i, now)).join('')}</TrustServiceProviderList>`
      : '') +
    '</TrustServiceStatusList>\n'
  );
}

let xmlDependencies = false;

/** Registers the DOM and XPath implementations xadesjs needs outside a browser, and Node.js's Web Crypto, once. */
function ensureXades() {
  if (xmlDependencies) return;
  xadesjs.setNodeDependencies({ DOMParser, XMLSerializer, DOMImplementation, xpath } as never);
  xadesjs.Application.setEngine('NodeJS', globalThis.crypto);
  xmlDependencies = true;
}

const EXCLUSIVE_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

/**
 * Signs a list with an enveloped XAdES-B-B signature (TS 119 612 clause 5.7, Annex B): one reference to the whole
 * `TrustServiceStatusList` (`URI=""`) with the enveloped-signature and exclusive canonicalization transforms, exclusive
 * canonicalization of `SignedInfo`, ECDSA with SHA-256, the signer certificate alone in `KeyInfo`, and the signed
 * properties `SigningTime`, `SigningCertificateV2` and `DataObjectFormat` (`text/xml`).
 */
export async function signTrustedList(xml: string, signer: CertifiedKey, now = new Date()): Promise<string> {
  ensureXades();
  const document = new DOMParser().parseFromString(xml, 'application/xml');
  const signedXml = new xadesjs.SignedXml();
  const referenceId = `r-${randomUUID()}`;
  signedXml.XmlSignature.SignedInfo.CanonicalizationMethod.Algorithm = EXCLUSIVE_C14N;
  const format = new xadesjs.xml.DataObjectFormat();
  format.ObjectReference = `#${referenceId}`;
  format.MimeType = 'text/xml';
  signedXml.SignedProperties.SignedDataObjectProperties.DataObjectFormats.Add(format);
  const certificate = Buffer.from(signer.certificate.der).toString('base64');
  const signature = await signedXml.Sign({ name: 'ECDSA', hash: 'SHA-256' } as Algorithm, signer.key.privateKey, document as never, {
    references: [{ id: referenceId, uri: '', hash: 'SHA-256', transforms: ['enveloped', 'exc-c14n'] }],
    x509: [certificate],
    signingCertificateV2: certificate,
    signingTime: { value: now },
  });
  document.documentElement?.appendChild(signature.GetXml() as never);
  return new XMLSerializer().serializeToString(document);
}

/** Builds and signs a list with the certificate of its scheme operator. */
export async function buildSignedTrustedList(options: TrustedListBuildOptions): Promise<string> {
  return signTrustedList(buildTrustedListXml(options), options.pki.trustedListOperators[options.list], options.now);
}

/**
 * The LOTL and `TL-QEAA` of a run, signed, for the given locations: `TL-QEAA` points to the LOTL, the LOTL to
 * `TL-QEAA` and to itself, each pointer with the certificate that signs the list it points to.
 */
export async function buildTrustedLists(options: {
  pki: TestPki;
  locations: Record<TrustedListId, string>;
  entities?: string[];
  sequenceNumber?: number;
  now?: Date;
}): Promise<Record<TrustedListId, string>> {
  const { pki, locations } = options;
  const lotlPointer: TrustedListPointer = { list: 'LOTL', location: locations.LOTL, signers: [pki.trustedListOperators.LOTL] };
  const qeaaPointer: TrustedListPointer = { list: 'TL-QEAA', location: locations['TL-QEAA'], signers: [pki.trustedListOperators['TL-QEAA']] };
  const common = { pki, sequenceNumber: options.sequenceNumber, now: options.now };
  return {
    LOTL: await buildSignedTrustedList({ ...common, list: 'LOTL', location: locations.LOTL, pointers: [qeaaPointer, lotlPointer] }),
    'TL-QEAA': await buildSignedTrustedList({
      ...common,
      list: 'TL-QEAA',
      location: locations['TL-QEAA'],
      pointers: [lotlPointer],
      entities: options.entities,
    }),
  };
}
