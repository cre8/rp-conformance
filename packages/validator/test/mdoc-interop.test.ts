import { identifierListToken, pid, presentation, statusListToken } from '@rp-conformance/core';
import {
  createTestPki,
  encodeCbor,
  oid4vpSessionTranscript,
  forgePresentation,
  generateEcKeyPair,
  jwkThumbprint,
  mdocContext,
  PID_DOCTYPE,
  PID_NAMESPACE,
  presentMdoc,
  requestedElements,
  PID_MDOC_QUERY,
} from '@rp-conformance/forge';
import { CoseKey, DeviceResponse, IdentifierListCwt, SessionTranscript, Verifier } from '@owf/mdoc';
import { StatusListCwt } from '@owf/token-status-list';
import { parseCertificate } from '@owf/x509';
import { describe, expect, it } from 'vitest';
import { openid4vpSessionTranscript } from '../src/index';

// Cross-check of the mdoc artifacts the harness builds and the Conformance Wallet presents, with the verifier of
// @owf/mdoc and @owf/token-status-list (which EUDIPLO uses), independent of the reference validator.
describe('mdoc artifacts against @owf/mdoc', () => {
  it('the DeviceResponse of a valid mdoc verifies: IssuerAuth, digests, validity and DeviceAuth', async () => {
    const pki = await createTestPki();
    const holder = await generateEcKeyPair();
    const forged = await forgePresentation(
      presentation({ query: 'default_query_pid_mdoc', credential: pid.mdoc(), statusList: statusListToken.cwt() }),
      { pki, holderPublicJwk: holder.publicJwk, allocateStatusUri: () => 'https://status.rp-test/interop/1', skewSeconds: 60 },
    );
    const encryptionKey = await generateEcKeyPair();
    const options = { clientId: 'x509_hash:interop', nonce: 'n-interop', responseUri: 'https://rp.rp-test/response', jwkThumbprint: await jwkThumbprint(encryptionKey.publicJwk) };
    const deviceResponse = await presentMdoc(forged.credential as Uint8Array, {
      handover: { flow: 'redirect', clientId: options.clientId, responseUri: options.responseUri },
      nonce: options.nonce,
      jwkThumbprint: options.jwkThumbprint,
      holderPrivateKey: holder.privateKey,
      elements: requestedElements(PID_MDOC_QUERY.credentials[0].claims),
    });
    const sessionTranscript = await SessionTranscript.forOid4Vp(options, mdocContext);
    const result = await Verifier.verifyDeviceResponse(
      {
        deviceResponse,
        sessionTranscript,
        trustedCertificates: [{ issuance: [pki.entities['PP-A'].anchors.issuance.certificate.der] }],
        disableCertificateChainValidation: true,
        disableStatusValidation: true,
      },
      mdocContext,
    );
    const [document] = result.documents;
    expect(document.document.docType).toBe(PID_DOCTYPE);
    expect(document.document.issuerSigned.getPrettyClaims(PID_NAMESPACE)).toMatchObject({ family_name: 'Mustermann', given_name: 'Erika' });
    expect(DeviceResponse.decode(deviceResponse).documents).toHaveLength(1);
  });

  it('the SessionTranscript of the reference validator equals that of @owf/mdoc, via redirects and via the DC API', async () => {
    const thumbprint = await jwkThumbprint((await generateEcKeyPair()).publicJwk);
    for (const handover of [
      { flow: 'redirect', clientId: 'x509_hash:interop', responseUri: 'https://rp.rp-test/response' },
      { flow: 'dc-api', origin: 'https://rp.rp-test' },
    ] as const) {
      for (const key of [thumbprint, null]) {
        const expected = await oid4vpSessionTranscript({ handover, nonce: 'n-interop', jwkThumbprint: key });
        const own = openid4vpSessionTranscript({ handover, nonce: 'n-interop', jwkThumbprint: key });
        expect(encodeCbor(own), `${handover.flow}, ${key ? 'encrypted' : 'unencrypted'}`).toEqual(encodeCbor(expected));
      }
    }
  });

  it('the Status List Token in CWT format and the identifier list verify', async () => {
    const pki = await createTestPki();
    const holder = await generateEcKeyPair();
    const ctx = { pki, holderPublicJwk: holder.publicJwk, skewSeconds: 60 };
    const withList = await forgePresentation(presentation({ query: 'default_query_pid_mdoc', credential: pid.mdoc() }), {
      ...ctx,
      allocateStatusUri: () => 'https://status.rp-test/interop/2',
    });
    const signer = pki.entities['PP-A'].signers.revocation.certificate;
    const key = CoseKey.fromJwk(parseCertificate(signer.der).publicKey.jwk as Record<string, unknown>);
    const statusList = StatusListCwt.fromToken(withList.statusList?.served.body as Uint8Array);
    await statusList.verify({ key, uri: 'https://status.rp-test/interop/2', idx: withList.statusList?.index }, { sign1: mdocContext.cose.sign1 });

    const withIdentifiers = await forgePresentation(
      presentation({ query: 'default_query_pid_mdoc', credential: pid.mdoc(), identifierList: identifierListToken.cwt({ contains: false }) }),
      { ...ctx, allocateStatusUri: () => 'https://status.rp-test/interop/3' },
    );
    const identifierList = IdentifierListCwt.fromToken(withIdentifiers.identifierList?.served.body as Uint8Array);
    await identifierList.verify(
      { key, uri: 'https://status.rp-test/interop/3', id: withIdentifiers.identifierList?.identifier },
      { sign1: mdocContext.cose.sign1 },
    );
  });
});
