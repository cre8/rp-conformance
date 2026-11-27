// RP_WS_MS_CredentialFormats: the DCQL query of the Relying Party's request.
import { formats, type FormatWording, ics, pidQueryOf, preconditions, relevancy } from '@eudi-pcaf/core';
import { requestTestCase } from '../requests';

const credentialFormats = (testCase: Omit<Parameters<typeof requestTestCase>[0], 'layer' | 'area'>) =>
  requestTestCase({ layer: 'MS', area: 'CredentialFormats', ...testCase });

const perFormat = (format: FormatWording) => [
  credentialFormats({
    number: 1,
    format,
    objective: `Verify that the DCQL query of the Relying Party's request for a credential in ${format.name} format is valid.`,
    references: ['[OpenID4VP] section 6, 7, B.2.3, B.3.5', '[HAIP] section 5.3.1, 5.3.2'],
    checks: ['dcql'],
    rule: `The credential queries have unique \`id\`s, the format \`${format.credentialFormat}\` with ${format.credentialFormat === 'mso_mdoc' ? '`meta.doctype_value`' : '`meta.vct_values`'}, and valid claims path pointers.`,
  }),
  credentialFormats({
    number: 2,
    format,
    relevancy: relevancy.specificRequired,
    objective: `Verify that the Relying Party requests only attributes in ${format.name} format that its registration certificate lists.`,
    references: ['[ETSI TS 119 475]', '[ARF] Annex 2, RPRC_19, RPRC_21'],
    checks: ['registered-attributes'],
    rule: 'Every credential and claim the DCQL query requests is covered by a credential and claim the registration certificate in `verifier_info` lists.',
  }),
  credentialFormats({
    number: 3,
    format,
    relevancy: relevancy.genericOptional,
    profile: [ics.usesTrustedAuthorities],
    preconditions: [preconditions.trustedAuthoritiesOfPpA],
    query: pidQueryOf(format.credentialFormat, { trustedAuthorities: true }),
    objective: `Verify that the \`trusted_authorities\` of the Relying Party's request for a credential in ${format.name} format names anchors of the list that is the root of trust of the requested category.`,
    references: ['[OpenID4VP] section 6.1.1.1', '[HAIP] section 5'],
    checks: ['trusted-authorities'],
    rule: 'Every `trusted_authorities` entry is of type `aki` and names only key identifiers of PID/Issuance anchors of `TL-PID`.',
  }),
  credentialFormats({
    number: 4,
    format,
    relevancy: relevancy.specificOptional,
    objective: `Verify that the Relying Party requests a PID in ${format.name} format with cryptographic holder binding.`,
    references: ['[OpenID4VP] section 6.1', '[ARF] section 6.6.3.8', '[ARF] Annex 2, OIA_17'],
    checks: ['holder-binding'],
    rule: 'No credential query for a PID sets `require_cryptographic_holder_binding` to false.',
  }),
];

export const definitions = [...perFormat(formats.sdJwtVc), ...perFormat(formats.mdoc)];
