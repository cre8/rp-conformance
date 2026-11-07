import { credential, signWRPRC, WRP_ENTITLEMENTS, wrprc } from '@owf/eudi-registration-certificate';
import type { DcqlQuery } from '@rp-conformance/core';
import { base64url, signEs256 } from './crypto';
import type { TestPki } from './pki';

/** The `organizationIdentifier` of the Relying Party's access certificate, which binds the registration certificate. */
export const RELYING_PARTY_IDENTIFIER = 'VATDE-123456789';

/**
 * Issues the Relying Party's registration certificate (ETSI TS 119 475) under `RC-A`. It lists the credentials
 * and claims of every default query the Relying Party uses, as `default_configuration_rp_1` requires.
 */
export async function issueRegistrationCertificate(pki: TestPki, queries: DcqlQuery[], now = new Date()): Promise<string> {
  const builder = wrprc()
    .name('RP conformance test Relying Party')
    .legalName('RP conformance test Relying Party')
    .identifier(RELYING_PARTY_IDENTIFIER)
    .country('DE')
    .registryUri('https://registry.rp-test/api')
    .serviceDescription('Relying Party under conformance test', 'en')
    .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
    .addPurpose('Conformance testing', 'en')
    .privacyPolicy('https://rp.rp-test/privacy')
    .supportUri('https://rp.rp-test/support')
    .issuedAt(now);
  for (const query of queries) {
    for (const credentialQuery of query.credentials) {
      const entry = credential().format(credentialQuery.format).meta(credentialQuery.meta ?? {});
      for (const claim of credentialQuery.claims ?? []) entry.addPathClaim(...claim.path);
      builder.addCredential(entry.build());
    }
  }
  const signer = pki.entities['RC-A'].signers.issuance;
  const signed = await signWRPRC({
    payload: builder.build(),
    accessCertificateSub: RELYING_PARTY_IDENTIFIER,
    certificates: signer.chain.map((certificate) => certificate.pem),
    signingTime: now,
    signer: async (data: string) => base64url.encode(await signEs256(signer.key.privateKey, data)),
  });
  return signed.jws;
}
