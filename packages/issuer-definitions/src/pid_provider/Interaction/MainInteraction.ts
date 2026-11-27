// PP_WS_IA_MainInteraction: the positive baseline of the issuer suite and the positive controls of its `_UF` test
// cases (issuer catalogue section 5.1.2). One definition per variant, expanded by a function as the RP definitions
// expand their formats: `SD` and `MD` × `PA` and `AC` (`AC` with issue 20).
import { defineIssuerTestCase, type FormatVariant, type GrantVariant, issuerProfiles, relevancy } from '@eudi-pcaf/core';
import { configurationOf, FORMAT_NAMES, GRANT_NAMES, iss, issuance, pidProfile, preconditions, technologyOf } from '../../wording';

const mainInteraction001 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_MainInteraction_001',
    variants: [format, grant],
    objective: `Verify that the PID Provider issues the PID in ${FORMAT_NAMES[format]} format to the Wallet Unit \`CW-1\` in the ${GRANT_NAMES[grant]}, and that the credential passes every check of the reference validator.`,
    references: ['[ARF] Annex 2, ISSU_01a, ISSU_14, ISSU_15', '[OpenID4VCI] sections 6, 7 and 8', '[HAIP] section 4'],
    profile: pidProfile(format, grant),
    relevancy: relevancy.specificRequired,
    technology: technologyOf(format),
    preconditions: preconditions.base,
    steps: [
      {
        text: `The adapter creates a credential offer for \`SUBJ-1\` and the PID configuration in ${FORMAT_NAMES[format]} format, ${grant === 'PA' ? 'pre-authorized code with `tx_code` unless the ICS declares offers without one' : 'authorization code with `issuer_state`'}. \`CW-1\` runs \`SCN-I\` without mutation: metadata, ${grant === 'PA' ? '' : 'pushed authorization request with PKCE `S256`, `authorization_details`, WIA, PoP and DPoP proof, the authorization request through the adapter (`authenticateSubject`), '}token request with WIA, PoP and DPoP proof${grant === 'PA' ? '' : ' and the `code_verifier`'}, nonce request, credential request with one \`openid4vci-proof+jwt\` that carries the KA.`,
        run: issuance(format, grant),
        expect: iss(format),
      },
    ],
    comments: [
      'Positive control of every `_UF` test case of the same variant (issuer catalogue section 3.7): a `_UF` test case is executed only after this one passed.',
      'Execute this test case once for each format and grant the Provider declares in its ICS (ICS-02, ICS-03).',
    ],
  });

/** `_003`: both formats of the PID in one authorization, one access token and two credential requests (ISSU_12a). */
const mainInteraction003 = (grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_MainInteraction_003',
    variants: [grant],
    objective: `Verify that the PID Provider issues the PID in both formats, SD-JWT VC and mdoc, in one authorization in the ${GRANT_NAMES[grant]}: one access token, two credential requests, and that both credentials pass every check of the reference validator.`,
    references: ['[ARF] Annex 2, ISSU_12, ISSU_12a', '[OpenID4VCI] sections 6 and 8'],
    profile: [issuerProfiles['P-PID'], issuerProfiles['P-SD'], issuerProfiles['P-MD'], issuerProfiles[`P-${grant}`]],
    relevancy: relevancy.specificRequired,
    technology: ['OpenID4VCI', 'SD-JWT VC', 'ISO/IEC 18013-5 mdoc'],
    preconditions: preconditions.base,
    steps: [
      {
        text: `The adapter creates one credential offer for \`SUBJ-1\` and the PID configurations in SD-JWT VC and mdoc format. \`CW-1\` runs \`SCN-I\` in the ${GRANT_NAMES[grant]} without mutation and, with the one access token, sends a credential request for each configuration, each with a fresh \`c_nonce\` and proof.`,
        run: issuance('SD', grant, { configurations: [configurationOf('SD'), configurationOf('MD')] }),
        expect: {
          codes: ['ISS'],
          text: 'The Provider issues both credentials (HTTP 200 to each credential request), one in SD-JWT VC format (`dc+sd-jwt`) and one in mdoc format (`mso_mdoc`). Every credential passes every check of the reference validator.',
        },
      },
    ],
    comments: ['Execute this test case once for each grant the Provider declares in its ICS (ICS-03).'],
  });

// SD+PA (issue 17); MD+PA and `_003` (issue 21, mdoc issuance); SD+AC and MD+AC (issue 20, authorization code flow).
export const definitions = [
  mainInteraction001('SD', 'PA'),
  mainInteraction001('MD', 'PA'),
  mainInteraction001('SD', 'AC'),
  mainInteraction001('MD', 'AC'),
  mainInteraction003('PA'),
  mainInteraction003('AC'),
];
