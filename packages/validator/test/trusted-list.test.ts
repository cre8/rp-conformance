import {
  ACTIVE_SERVICE_STATUSES,
  getPointerSigningCertificates,
  getTrustAnchors,
  loadTrustedList,
  TrustedListProfiles,
  validateTrustedListProfile,
} from '@owf/eudi-tl';
import {
  buildSignedTrustedList,
  buildTrustedListXml,
  buildTrustedLists,
  createTestPki,
  EAA_SERVICE_TYPE,
  SERVICE_STATUS,
  signTrustedList,
  TSL_SIGNING_EXTENDED_KEY_USAGE,
  TSL_TYPE,
  type TestPki,
} from '@rp-conformance/forge';
import { DOMParser } from '@xmldom/xmldom';
import { createHash } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { TRUST_RULES, TrustStore } from '../src/index';

// Harness design section 7 for the lists in ETSI TS 119 612 format: the LOTL and TL-QEAA the forge signs with xadesjs
// are accepted by @owf/eudi-tl, which only parses and verifies Trusted Lists, and carry what TS 119 612 V2.4.1 requires
// of their signature (clause 5.7, Annex B) and content. A list that is changed, signed by another key or expired is
// not used.

const LOCATIONS = { LOTL: 'https://trust.rp-test/tl/LOTL.xml', 'TL-QEAA': 'https://trust.rp-test/tl/TL-QEAA.xml' };
const DSIG = 'http://www.w3.org/2000/09/xmldsig#';
const XADES = 'http://uri.etsi.org/01903/v1.3.2#';

let pki: TestPki;
let lists: Awaited<ReturnType<typeof buildTrustedLists>>;

beforeAll(async () => {
  pki = await createTestPki();
  lists = await buildTrustedLists({ pki, locations: LOCATIONS });
});

const storeFor = (served: Record<string, string>) =>
  new TrustStore(
    { lotes: [], listOfTrustedLists: { url: LOCATIONS.LOTL, signingCertificatesPem: [pki.trustedListOperators.LOTL.certificate.pem] } },
    (async (url: string) => (served[String(url)] ? new Response(served[String(url)]) : new Response('not found', { status: 404 }))) as typeof fetch,
  );

describe('LOTL and TL-QEAA in ETSI TS 119 612 format', () => {
  it('@owf/eudi-tl verifies the LOTL with its signing certificate and TL-QEAA with the certificate of the LOTL pointer', async () => {
    const lotl = await loadTrustedList(lists.LOTL, { trustAnchors: [pki.trustedListOperators.LOTL.certificate.der] });
    expect(validateTrustedListProfile(lotl, TrustedListProfiles.euLotl)).toEqual({ valid: true, issues: [] });
    expect(lotl.tslType).toBe(TSL_TYPE.EUlistofthelists);
    const pointerCertificates = getPointerSigningCertificates(lotl, { location: LOCATIONS['TL-QEAA'] });
    expect(pointerCertificates).toEqual([new Uint8Array(pki.trustedListOperators['TL-QEAA'].certificate.der)]);

    const tl = await loadTrustedList(lists['TL-QEAA'], { trustAnchors: pointerCertificates });
    expect(tl).toMatchObject({ tslType: TSL_TYPE.EUgeneric, schemeTerritory: 'DE', sequenceNumber: 1 });
    expect(tl.pointersToOtherLists?.map((p) => [p.location, p.tslType, p.schemeTerritory])).toEqual([[LOCATIONS.LOTL, TSL_TYPE.EUlistofthelists, 'EU']]);
    const anchors = getTrustAnchors(tl, { requireCertificate: true }).map((a) => [a.providerName, a.serviceTypeIdentifier, a.serviceStatus, a.subjectName]);
    expect(anchors).toEqual([
      ['QP-A', EAA_SERVICE_TYPE.qualified, SERVICE_STATUS.granted, 'CN=CA-QP-A,O=QP-A,C=DE'],
      ['QP-N', EAA_SERVICE_TYPE.notQualified, SERVICE_STATUS.recognisedAtNationalLevel, 'CN=CA-QP-N,O=QP-N,C=DE'],
      ['QP-W', EAA_SERVICE_TYPE.qualified, SERVICE_STATUS.withdrawn, 'CN=CA-QP-W,O=QP-W,C=DE'],
    ]);
    // The withdrawn service keeps its granted status in its history (clause 5.5.10).
    const qpW = tl.providers.find((p) => p.name === 'QP-W')?.services[0];
    expect(qpW?.history?.map((h) => h.serviceStatus)).toEqual([SERVICE_STATUS.granted]);
    // Only QP-A has an active qualified service for the issuance of QEAAs.
    expect(
      getTrustAnchors(tl, { serviceStatus: ACTIVE_SERVICE_STATUSES, serviceTypeIdentifier: [EAA_SERVICE_TYPE.qualified] }).map((a) => a.providerName),
    ).toEqual(['QP-A']);
  });

  it.each(['LOTL', 'TL-QEAA'] as const)('%s carries an enveloped XAdES-B-B signature as TS 119 612 Annex B requires', (list) => {
    const document = new DOMParser().parseFromString(lists[list], 'application/xml');
    const root = document.documentElement;
    expect(root?.localName).toBe('TrustServiceStatusList');
    expect(root?.getAttribute('TSLTag')).toBe('http://uri.etsi.org/19612/TSLTag');
    const signatures = document.getElementsByTagNameNS(DSIG, 'Signature');
    expect(signatures).toHaveLength(1);
    const signature = signatures[0];
    // The signature is the last child of TrustServiceStatusList (enveloped).
    expect(signature.parentNode).toBe(root);
    const byName = (ns: string, name: string) => Array.from(signature.getElementsByTagNameNS(ns, name));
    expect(byName(DSIG, 'CanonicalizationMethod')[0].getAttribute('Algorithm')).toBe('http://www.w3.org/2001/10/xml-exc-c14n#');
    expect(byName(DSIG, 'SignatureMethod')[0].getAttribute('Algorithm')).toBe('http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256');
    const references = byName(DSIG, 'Reference');
    const whole = references.filter((r) => r.getAttribute('URI') === '');
    expect(whole).toHaveLength(1);
    expect(Array.from(whole[0].getElementsByTagNameNS(DSIG, 'Transforms'))).toHaveLength(1);
    expect(Array.from(whole[0].getElementsByTagNameNS(DSIG, 'Transform')).map((t) => t.getAttribute('Algorithm'))).toEqual([
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ]);
    expect(references.filter((r) => r.getAttribute('Type') === 'http://uri.etsi.org/01903#SignedProperties')).toHaveLength(1);
    // KeyInfo holds the scheme operator certificate and no other certificate (clause 5.7.1).
    const operator = pki.trustedListOperators[list].certificate;
    const keyInfoCertificates = byName(DSIG, 'KeyInfo').flatMap((k) => Array.from(k.getElementsByTagNameNS(DSIG, 'X509Certificate')));
    expect(keyInfoCertificates.map((c) => c.textContent?.replace(/\s/g, ''))).toEqual([Buffer.from(operator.der).toString('base64')]);
    // XAdES-B-B signed properties: SigningTime, SigningCertificateV2 over the scheme operator certificate (B.1.1), and
    // DataObjectFormat for the list.
    expect(byName(XADES, 'SigningTime')).toHaveLength(1);
    const certDigest = byName(XADES, 'SigningCertificateV2')[0]?.getElementsByTagNameNS(DSIG, 'DigestValue')[0]?.textContent;
    expect(certDigest).toBe(createHash('sha256').update(operator.der).digest('base64'));
    const format = byName(XADES, 'DataObjectFormat')[0];
    expect(format?.getAttribute('ObjectReference')).toBe(`#${whole[0].getAttribute('Id')}`);
    expect(format?.getElementsByTagNameNS(XADES, 'MimeType')[0]?.textContent).toBe('text/xml');
  });

  it.each(['LOTL', 'TL-QEAA'] as const)('the certificate that signs %s has the profile of TS 119 612 clause 5.7.1', (list) => {
    const { certificate } = pki.trustedListOperators[list];
    expect(certificate.issuer.rfc4514).toBe(certificate.subject.rfc4514);
    expect(certificate.subject.rfc4514).toMatch(list === 'LOTL' ? /O=RP conformance test LOTL scheme operator,C=EU$/ : /O=RP conformance test TL-QEAA scheme operator,C=DE$/);
    expect(certificate.keyUsage).toEqual(['digitalSignature']);
    expect(certificate.extendedKeyUsage).toEqual([TSL_SIGNING_EXTENDED_KEY_USAGE]);
    expect(certificate.subjectKeyIdentifier).toBeTruthy();
    expect(certificate.basicConstraints?.cA ?? false).toBe(false);
  });

  it('a changed TL-QEAA, or one signed by a key other than that of the LOTL pointer, is refused', async () => {
    const anchors = [new Uint8Array(pki.trustedListOperators['TL-QEAA'].certificate.der)];
    await expect(loadTrustedList(lists['TL-QEAA'].replace('<Name xml:lang="en">QP-N</Name>', '<Name xml:lang="en">QP-X</Name>'), { trustAnchors: anchors })).rejects.toThrow();
    const xml = buildTrustedListXml({ list: 'TL-QEAA', pki, location: LOCATIONS['TL-QEAA'], pointers: [] });
    const foreign = await signTrustedList(xml, pki.entities['CA-X'].signers.issuance);
    await expect(loadTrustedList(foreign, { trustAnchors: anchors })).rejects.toThrow(/not among the configured trust anchors/);
  });
});

describe('the reference validator trusts QEAAs through the LOTL', () => {
  it('loads the LOTL and TL-QEAA, logs both retrievals, and trusts only the granted qualified service of QP-A', async () => {
    const store = storeFor({ [LOCATIONS.LOTL]: lists.LOTL, [LOCATIONS['TL-QEAA']]: lists['TL-QEAA'] });
    expect((await store.refresh()).filter((r) => r.error)).toEqual([]);
    expect(store.retrievals.map((r) => [r.url, r.status])).toEqual([
      [LOCATIONS.LOTL, 200],
      [LOCATIONS['TL-QEAA'], 200],
    ]);
    const chainOf = (id: string) => [Buffer.from(pki.entities[id].signers.issuance.certificate.der).toString('base64')];
    const qpA = await store.match(TRUST_RULES.qeaa, chainOf('QP-A'));
    expect(qpA.ok && [qpA.entity.name, qpA.service.type, qpA.service.status]).toEqual(['QP-A', EAA_SERVICE_TYPE.qualified, SERVICE_STATUS.granted]);
    // Status lists of a QEAA are signed under the anchor of the service that validated it.
    expect(qpA.ok && TRUST_RULES.qeaa.statusAnchors(qpA.entity, qpA.service).map((a) => a.subject.commonName)).toEqual(['CA-QP-A']);
    for (const id of ['QP-N', 'QP-W', 'PP-A', 'PB-A', 'EP-A']) expect((await store.match(TRUST_RULES.qeaa, chainOf(id))).ok, id).toBe(false);
    // A QTSP of TL-QEAA is no PID Provider (TrustMechanisms_002).
    expect((await store.match(TRUST_RULES.pid, chainOf('QP-A'))).ok).toBe(false);
  });

  it('refuses a LOTL signed by another key, and a TL-QEAA whose NextUpdate has passed', async () => {
    const foreignLotl = await signTrustedList(buildTrustedListXml({ list: 'LOTL', pki, location: LOCATIONS.LOTL, pointers: [] }), pki.trustedListOperators['TL-QEAA']);
    const forged = storeFor({ [LOCATIONS.LOTL]: foreignLotl, [LOCATIONS['TL-QEAA']]: lists['TL-QEAA'] });
    expect((await forged.refresh()).map((r) => r.error ?? 'ok')).toEqual([expect.stringMatching(/not among the configured trust anchors/)]);
    expect([...forged.lists.values()].filter((l) => l.kind === 'trusted-list')).toEqual([]);

    const expired = await buildSignedTrustedList({
      list: 'TL-QEAA',
      pki,
      location: LOCATIONS['TL-QEAA'],
      pointers: [],
      now: new Date(Date.now() - 40 * 24 * 60 * 60 * 1000),
    });
    const stale = storeFor({ [LOCATIONS.LOTL]: lists.LOTL, [LOCATIONS['TL-QEAA']]: expired });
    const results = await stale.refresh();
    expect(results.find((r) => r.id !== 'LOTL')?.error).toMatch(/NextUpdate .* has passed/);
    expect((await stale.match(TRUST_RULES.qeaa, [Buffer.from(pki.entities['QP-A'].signers.issuance.certificate.der).toString('base64')])).ok).toBe(false);
  });

  it('trusts the rulebook anchor CA-EP-A for non-qualified EAAs only', async () => {
    const store = new TrustStore({ lotes: [], rulebooks: [{ credential: 'default_credential_eaa', anchorsPem: [pki.entities['EP-A'].anchors.issuance.certificate.pem] }] });
    await store.refresh();
    const chainOf = (id: string) => [Buffer.from(pki.entities[id].signers.issuance.certificate.der).toString('base64')];
    expect((await store.match(TRUST_RULES.eaa, chainOf('EP-A'))).ok).toBe(true);
    expect((await store.match(TRUST_RULES.eaa, chainOf('PP-A'))).ok).toBe(false);
    expect((await store.match(TRUST_RULES.pid, chainOf('EP-A'))).ok).toBe(false);
  });
});
