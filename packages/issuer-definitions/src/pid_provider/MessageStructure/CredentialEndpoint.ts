// PP_WS_MS_CredentialEndpoint (issuer catalogue section 5.1.1): the credential request, valid and with one fault of the
// point `credential-request` each (issuer harness design section 6.2). Every step runs `SCN-I`; offer, metadata,
// token and nonce request are valid, the fault changes the credential request only.
import { CREDENTIAL_REQUEST_FAULTS, type CredentialRequestFaultId, defineIssuerTestCase, type FormatVariant, type GrantVariant, relevancy } from '@eudi-pcaf/core';
import { FORMAT_NAMES, GRANT_NAMES, iss, issuance, pidProfile, preconditions, rej, technologyOf } from '../../wording';

const CONTROL = 'PP_WS_IA_MainInteraction_001';

const scn = (format: FormatVariant, grant: GrantVariant, fault?: CredentialRequestFaultId) =>
  `The adapter creates a credential offer for \`SUBJ-1\` and the PID configuration in ${FORMAT_NAMES[format]} format, ${GRANT_NAMES[grant]}. \`CW-1\` runs \`SCN-I\`${fault ? `, except that ${CREDENTIAL_REQUEST_FAULTS[fault].text}` : ' without mutation'}.`;

const base = (format: FormatVariant, grant: GrantVariant, gated: boolean) => ({
  variants: [format, grant],
  profile: pidProfile(format, grant),
  technology: technologyOf(format),
  preconditions: gated ? [...preconditions.base, preconditions.control(CONTROL)] : preconditions.base,
  ...(gated ? { control: CONTROL } : {}),
});

const faulty = (format: FormatVariant, grant: GrantVariant, fault: CredentialRequestFaultId, options: { credentialIdentifier?: boolean } = {}) => ({
  text: scn(format, grant, fault),
  run: issuance(format, grant, { faults: [fault], ...options }),
});

const ce001 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_MS_CredentialEndpoint_001',
    ...base(format, grant, false),
    objective: 'Verify that a valid credential request with `credential_configuration_id` and `proofs` is answered with `credentials`, an array of objects with `credential`.',
    references: ['[OpenID4VCI] sections 8.2 and 8.3'],
    relevancy: relevancy.genericRequired,
    steps: [
      {
        text: `${scn(format, grant)} The credential request names the configuration by \`credential_configuration_id\` and carries one proof in \`proofs.jwt\`.`,
        run: issuance(format, grant),
        expect: { ...iss(format), text: `The credential response carries \`credentials\`, an array of objects each with a \`credential\` member. ${iss(format).text}` },
      },
    ],
  });

const ce002 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_MS_CredentialEndpoint_002',
    ...base(format, 'AC', false),
    objective: 'Verify that, when the token response carried `authorization_details` with `credential_identifiers`, a credential request with `credential_identifier` succeeds.',
    references: ['[OpenID4VCI] sections 6.2 and 8.2'],
    relevancy: relevancy.genericRequired,
    steps: [
      {
        text: `${scn(format, 'AC')} The credential request names the first \`credential_identifier\` of the token response's \`authorization_details\` instead of \`credential_configuration_id\`.`,
        run: issuance(format, 'AC', { credentialIdentifier: true }),
        expect: iss(format),
      },
    ],
  });

const ce003 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_MS_CredentialEndpoint_003_UF',
    ...base(format, grant, true),
    objective: 'Verify that a credential request for an unknown `credential_configuration_id` is rejected.',
    references: ['[OpenID4VCI] section 8.3.1.2'],
    relevancy: relevancy.genericRequired,
    steps: [{ ...faulty(format, grant, 'credential-request.configuration-unknown'), expect: rej('unknown_credential_configuration') }],
  });

const ce004 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_MS_CredentialEndpoint_004_UF',
    ...base(format, grant, true),
    objective: 'Verify that a credential request for a configuration the access token was not issued for is rejected.',
    references: ['[OpenID4VCI] sections 8.2 and 8.3.1.2'],
    relevancy: relevancy.genericRequired,
    steps: [{ ...faulty(format, grant, 'credential-request.configuration-not-authorized'), expect: rej() }],
    comments: ['The Provider must offer a second credential configuration in its metadata; without one the step is INCONCLUSIVE.'],
  });

const ce005 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_MS_CredentialEndpoint_005_UF',
    ...base(format, grant, true),
    objective: 'Verify that a credential request with both `credential_identifier` and `credential_configuration_id`, or with neither, is rejected.',
    references: ['[OpenID4VCI] section 8.2'],
    relevancy: relevancy.genericRequired,
    steps: [
      { ...faulty(format, grant, 'credential-request.both-identifiers'), expect: rej('invalid_credential_request') },
      { ...faulty(format, grant, 'credential-request.no-identifier'), expect: rej('invalid_credential_request') },
    ],
    comments: ['Step 1 needs a token response with `credential_identifiers` for the configuration; without them the step is INCONCLUSIVE.'],
  });

const ce006 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_MS_CredentialEndpoint_006_UF',
    ...base(format, 'AC', true),
    objective: 'Verify that a credential request with a `credential_identifier` not issued in this token response is rejected.',
    references: ['[OpenID4VCI] section 8.3.1.2'],
    relevancy: relevancy.genericRequired,
    steps: [{ ...faulty(format, 'AC', 'credential-request.identifier-foreign', { credentialIdentifier: true }), expect: rej('unknown_credential_identifier') }],
  });

const ce007 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_MS_CredentialEndpoint_007',
    ...base(format, grant, false),
    objective: 'Verify that unknown parameters of a credential request are ignored.',
    references: ['[OpenID4VCI] section 8.2'],
    relevancy: relevancy.genericRequired,
    steps: [{ ...faulty(format, grant, 'credential-request.extra-member'), expect: iss(format) }],
  });

const GRANTS: GrantVariant[] = ['PA', 'AC'];

export const definitions = [
  ...GRANTS.map((g) => ce001('SD', g)),
  ce002('SD'),
  ...GRANTS.map((g) => ce003('SD', g)),
  ...GRANTS.map((g) => ce004('SD', g)),
  ...GRANTS.map((g) => ce005('SD', g)),
  ce006('SD'),
  ...GRANTS.map((g) => ce007('SD', g)),
];
