// RP_WS_MS_Metadata: the `client_metadata` of the Relying Party's request, with the key the Authorization Response is
// encrypted to and the formats and algorithms it accepts.
import { formats, type FormatWording, relevancy } from '@eudi-pcaf/core';
import { requestTestCase } from '../requests';

const metadata = (testCase: Omit<Parameters<typeof requestTestCase>[0], 'layer' | 'area'>) => requestTestCase({ layer: 'MS', area: 'Metadata', ...testCase });

const vpFormats = (format: FormatWording) =>
  metadata({
    number: 4,
    format,
    relevancy: relevancy.specificRequired,
    objective: `Verify that the \`vp_formats_supported\` of the Relying Party's request covers the ${format.name} format it requests, with agreed algorithms only.`,
    references: ['[OpenID4VP] section 11.1, B.2.2, B.3.4', '[ECCG ACM]', '[ARF] Annex 2, OIA_03'],
    checks: ['vp-formats'],
    rule: `\`client_metadata\` carries \`vp_formats_supported\` with an entry for \`${format.credentialFormat}\`, and every algorithm it lists belongs to the agreed cryptographic mechanisms.`,
  });

export const definitions = [
  metadata({
    number: 1,
    objective: 'Verify that the request of the Relying Party carries a public encryption key for the response in `client_metadata`.',
    references: ['[HAIP] section 5', '[OpenID4VP] section 8.3, 11.1'],
    checks: ['encryption-key'],
    rule: '`client_metadata.jwks` holds an EC key on P-256 with `alg` `ECDH-ES` and a `kid`, and no key in it carries a private key member.',
  }),
  metadata({
    number: 2,
    objective: 'Verify that the Relying Party accepts both content encryption algorithms of the profile for the response.',
    references: ['[HAIP] section 5'],
    checks: ['enc-values'],
    rule: '`encrypted_response_enc_values_supported` lists both `A128GCM` and `A256GCM`.',
  }),
  metadata({
    number: 3,
    count: 20,
    objective: 'Verify that the Relying Party uses an ephemeral encryption key: a different one for every request.',
    references: ['[HAIP] section 5', '[OpenID4VP] section 8.3'],
    checks: ['ephemeral-key'],
    rule: 'Every request carries an encryption key, and no two requests carry the same key.',
  }),
  vpFormats(formats.sdJwtVc),
  vpFormats(formats.mdoc),
];
