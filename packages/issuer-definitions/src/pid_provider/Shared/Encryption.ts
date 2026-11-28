// PP_WS_SH_Encryption (`P-ENC`, issuer catalogue section 5.1.5): credential request and response encryption. The
// request is a JWE (`ECDH-ES`) to the key in `credential_request_encryption`; `credential_response_encryption` carries
// an ephemeral P-256 key of the Conformance Wallet.
import { defineIssuerTestCase, type FormatVariant, type GrantVariant, relevancy } from '@eudi-pcaf/core';
import { iss, issuance, preconditions, rej, technologyOf } from '../../wording';
import { FORMAT, faultStep, GRANT, MAIN, profileOf, ufPreconditions } from '../session';

const VCI = '[OpenID4VCI]';

const encryption001 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SH_Encryption_001',
    variants: [format, grant],
    objective: 'Verify that with `credential_response_encryption` the PID Provider answers with a JWE to the key of the Wallet Unit, with an advertised `alg` and `enc`.',
    references: [`${VCI} section 8.2`, `${VCI} section 8.3`, `${VCI} section 10`],
    profile: profileOf(format, grant, 'P-ENC'),
    relevancy: relevancy.genericOptional,
    technology: technologyOf(format),
    preconditions: preconditions.base,
    steps: [
      {
        text: '`CW-1` runs `SCN-I` for `SUBJ-1` without mutation, except that the credential request is a JWE (`ECDH-ES`, the first advertised `enc`) to the key of `credential_request_encryption`, and carries `credential_response_encryption` with an ephemeral P-256 key (`alg` `ECDH-ES`) and the first advertised `enc`.',
        run: issuance(format, grant, { encryption: true }),
        expect: {
          ...iss(format),
          text: `The Provider answers with a JWE (\`application/jwt\`) that \`CW-1\` decrypts with its ephemeral key. ${iss(format).text}`,
        },
      },
    ],
  });

const encryption002 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SH_Encryption_002_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that the PID Provider rejects credential response encryption with an `alg` or `enc` it does not advertise.',
    references: [`${VCI} section 8.3.1.2`],
    profile: profileOf(format, grant, 'P-ENC'),
    relevancy: relevancy.genericOptional,
    technology: technologyOf(format),
    preconditions: ufPreconditions(),
    steps: (['encryption.alg-unsupported', 'encryption.enc-unsupported'] as const).map((fault) => faultStep(format, grant, fault, rej('invalid_encryption_parameters'), { encryption: true })),
  });

const encryption003 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SH_Encryption_003_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that the PID Provider rejects a JWK for response encryption whose point is not on its curve.',
    references: ['[RFC 8725] section 3.4'],
    profile: profileOf(format, grant, 'P-ENC'),
    relevancy: relevancy.genericOptional,
    technology: technologyOf(format),
    preconditions: ufPreconditions(),
    steps: [faultStep(format, grant, 'encryption.off-curve-jwk', rej(), { encryption: true })],
  });

export const definitions = [encryption001, encryption002, encryption003].map((d) => d(FORMAT, GRANT));
