// PP_RP_SM_Revocation_001 to _008 (issuer catalogue section 5.2, `SCN-P`): the Status List Tokens the Provider publishes,
// as the RP catalogue's `RP_PP_*` and `RP_WS_SM_Revocation` tests assume them. `_001` names `SD` and `MD`, `_007` `MD`
// (identifier lists, `P-IL`); the others name no format and run in `SD` until the mdoc PID lands (issue 21). Every one
// runs in `PA`: the grant does not change what is published.
import { defineIssuerTestCase, type FormatVariant, issuerProfiles, relevancy } from '@eudi-pcaf/core';
import { fetchStep, issueStep, LIST_FORMAT, published, revokedStep, revokeStep } from '../../status';
import { FORMAT_NAMES, pidProfile, preconditions, technologyOf } from '../../wording';

const base = (format: FormatVariant) => ({
  variants: [format, 'PA'] as ('SD' | 'MD' | 'PA')[],
  profile: [...pidProfile(format, 'PA'), issuerProfiles['P-REV']],
  technology: [...technologyOf(format), 'Token Status List'],
  preconditions: preconditions.base,
});

const revocation001 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_RP_SM_Revocation_001',
    ...base(format),
    objective: `Verify that the Status List Token the ${FORMAT_NAMES[format]} PID references has the correct \`typ\`, \`sub\` equal to the credential's status \`uri\`, \`iat\`, an \`exp\` in the future and \`ttl\`.`,
    references: ['[TokenStatusList] sections 5.1 and 5.2'],
    relevancy: relevancy.genericRequired,
    steps: [
      issueStep(format),
      fetchStep(
        format,
        [1],
        published(['status-list-type', 'status-list-claims', 'status-list-subject', 'status-list-validity', 'sl-lifetime'], `The Status List Token in ${LIST_FORMAT[format]} carries the claims Token Status List requires and recommends.`),
      ),
    ],
    comments: ['`ttl` and `exp` are RECOMMENDED by Token Status List; the catalogue requires both, since `PP_RP_SM_Revocation_005` and `PP_RP_IA_Supportive_002` rely on them.'],
  });

const revocation002 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_RP_SM_Revocation_002',
    ...base(format),
    objective:
      'Verify that the Status List Token is signed under the revocation anchor of the Provider on its trusted list, or under its issuance anchor where the list carries that anchor under both services.',
    references: ['[ARF] Annex 2, PPNot_03a, PuBPNot_05', '[RP catalogue] decision 3'],
    relevancy: relevancy.specificRequired,
    steps: [issueStep(format), fetchStep(format, [1], published(['status-list-trust', 'status-list-signature'], 'A Relying Party with `TL-PID` validates the Status List Token to the Provider.'))],
    comments: ['OIDF `happy-flow` covers this objective partly: `x5c` chains to the configured status anchor, without the anchor category (issuer catalogue section 7).'],
  });

const revocation003 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_RP_SM_Revocation_003',
    ...base(format),
    objective: '`bits` of the Status List Token is 1, 2, 4 or 8, and `lst` is valid compressed data whose size covers the entries the list declares, including the credential\'s index.',
    references: ['[TokenStatusList] section 4.1'],
    relevancy: relevancy.genericRequired,
    steps: [issueStep(format), fetchStep(format, [1], published(['status-list-decoding', 'status-index', 'status'], 'The list decodes as Token Status List section 4.1 defines it.'))],
    comments: ['Token Status List declares the number of entries only through the size of `lst`: it must hold a whole number of entries of `bits` each, and the credential\'s `idx` must be one of them.'],
  });

const revocation004 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_RP_SM_Revocation_004',
    ...base(format),
    objective: 'Verify that the status list holds at least the minimum number of entries the Provider declares, and at least 10 000, so a Relying Party cannot single out the credential (herd privacy).',
    references: ['[ARF] Annex 2, VCR_18', 'ICS-16', '[Issuer catalogue] decision 4'],
    relevancy: relevancy.specificRequired,
    steps: [issueStep(format), fetchStep(format, [1], published(['status-list-decoding', 'sl-entries'], 'The list is large enough for herd privacy.'))],
    comments: ['The floor of 10 000 entries holds until the EC or ETSI sets a number (issuer catalogue decision 4).'],
  });

const revocation005 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_RP_SM_Revocation_005',
    ...base(format),
    objective: "Verify that the Provider publishes a new version of the status list before the previous one's `exp`, so a Relying Party never has only an expired token.",
    references: ['[TokenStatusList] section 8.3', '[ARF] Annex 2, VCR_14'],
    relevancy: relevancy.specificRequired,
    steps: [
      issueStep(format),
      {
        text: "The harness polls the status list anonymously every `min(t / 20, 30 s)`, where `t` is the time to the first version's `exp`, until two intervals after that `exp`, keeping every version with its `iat` and `exp`.",
        run: { kind: 'observe-status', ofSteps: [1], t: 'exp' },
        expect: published(['sl-lifetime', 'sl-continuity'], 'Every poll, before and after the first version expires, returns a token that has not expired.'),
      },
    ],
    comments: [
      'Long running: the step waits for the token lifetime, which the adapter sets to the shortest the Provider allows (issue 22); it runs after the other test cases.',
      'A Provider that signs a new version only on request still passes: what counts is that no fetch returns an expired token.',
    ],
  });

const revocation006 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_RP_SM_Revocation_006',
    ...base(format),
    objective: 'Verify that the Status List Token is signed with an ECCG agreed algorithm, and that its signer certificate is valid for the whole validity of the token.',
    references: ['[ARF] Annex 2, OIA_03', '[RFC 5280] section 4.1.2.5'],
    relevancy: relevancy.specificRequired,
    steps: [issueStep(format), fetchStep(format, [1], published(['sl-algorithm', 'sl-signer-validity'], 'A Relying Party can verify the token for as long as it is valid.'))],
    comments: ['ECCG agreed: ECDSA on P-256, P-384, P-521 and brainpoolP256r1, P384r1, P512r1 (SOG-IS Agreed Cryptographic Mechanisms).'],
  });

const revocation007 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_RP_SM_Revocation_007',
    ...base(format),
    profile: [...base(format).profile, issuerProfiles['P-IL']],
    objective: 'Verify that the identifier list the mdoc PID references has a valid signature under the revocation anchor, the structure of ISO/IEC 18013-5, and lists a revoked credential by its identifier.',
    references: ['[ARF] Annex 2, VCR_11', '[ISO/IEC 18013-5] second edition, section 12.3.6.4'],
    relevancy: relevancy.specificRequired,
    steps: [
      issueStep(format),
      {
        text: 'The harness fetches the identifier list the MSO references, anonymously.',
        run: { kind: 'observe-status', ofSteps: [1], t: 'PT0S' },
        expect: published(['identifier-list-trust', 'identifier-list-signature', 'identifier-list-claims', 'identifier-status'], 'The identifier list is the Provider\'s and does not list the fresh credential.'),
      },
      revokeStep(1),
      revokedStep(1),
    ],
    comments: ['Not executable against a Provider without identifier lists (`P-IL` No): NOT APPLICABLE. Reading identifier lists in `observe-status` comes with the first Provider that publishes them.'],
  });

const revocation008 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_RP_SM_Revocation_008',
    ...base(format),
    profile: [...base(format).profile, issuerProfiles['P-HOOK']],
    objective:
      "Verify that the Provider's revocation anchor and the signer it uses pass the reference Relying Party's checks: the reference Relying Party accepts a fresh PID the Provider issued and rejects it once the Provider has revoked it.",
    references: ['[ARF] Annex 2, VCR_11, VCR_11a', '[RP catalogue] `RP_WS_SM_Revocation`'],
    relevancy: relevancy.specificRequired,
    preconditions: [...preconditions.base, 'The adapter can revoke an issued credential (ICS-06, `P-HOOK`).', 'The reference Relying Party trusts `TL-PID` as published after enrolment, and `TL-AC` for its own access certificate.'],
    steps: [
      issueStep(format),
      {
        text: 'The reference Relying Party starts a presentation of `default_query_pid` over redirects; the Conformance Wallet presents the credential of step 1 with a KB-JWT signed with the key of its proof.',
        run: { kind: 'present', ofStep: 1 },
        expect: { codes: ['ACC'], text: 'The reference Relying Party accepts the presentation: every credential and status list check passes, the status is `0x00`.' },
      },
      revokeStep(1),
      revokedStep(1),
      {
        text: 'The reference Relying Party starts a new presentation of `default_query_pid`; the Conformance Wallet presents the credential of step 1 again.',
        run: { kind: 'present', ofStep: 1 },
        expect: { codes: ['REJ'], text: 'The reference Relying Party rejects the presentation, and the check that fails is `status`: the list shows the credential revoked; every other check passes.' },
      },
    ],
    comments: ['Long running: step 4 waits `T_rev`; the test case runs after the others.'],
  });

export const definitions = [
  revocation001('SD'),
  revocation001('MD'),
  revocation002('SD'),
  revocation003('SD'),
  revocation004('SD'),
  revocation005('SD'),
  revocation006('SD'),
  revocation007('MD'),
  revocation008('SD'),
];
