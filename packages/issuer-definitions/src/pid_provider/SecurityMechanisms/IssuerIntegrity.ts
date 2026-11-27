// PP_WS_SM_IssuerIntegrity (issue 26; issuer catalogue section 5.1.3): what the Provider signs, checked by the reference
// validator on `OBS-CRED`. Each test case runs `SCN-I` without mutation (`ISS`, which includes `issuer-trust` to `PP-T`),
// then inspects the credential with the named checks. A test case that names no format runs in `SD` and `MD`; each runs
// in `PA` (`AC` follows with the authorization code flow).
import { defineIssuerTestCase, type FormatVariant, type IssuerInspectionCheck, relevancy } from '@eudi-pcaf/core';
import { inspected, inspectStep, unitIssuance } from '../../inspection';
import { FORMAT_NAMES, pidProfile, preconditions, technologyOf } from '../../wording';

interface Integrity {
  id: string;
  objective: (format: FormatVariant) => string;
  references: string[];
  checks: (format: FormatVariant) => IssuerInspectionCheck[];
  what: (format: FormatVariant) => string;
  formats: FormatVariant[];
  relevancy?: (typeof relevancy)[keyof typeof relevancy];
  comments?: string[];
}

const integrity = (spec: Integrity) =>
  spec.formats.map((format) =>
    defineIssuerTestCase({
      id: spec.id,
      variants: [format, 'PA'],
      objective: spec.objective(format),
      references: spec.references,
      profile: pidProfile(format, 'PA'),
      relevancy: spec.relevancy ?? relevancy.specificRequired,
      technology: technologyOf(format),
      preconditions: preconditions.base,
      steps: [
        unitIssuance(format),
        inspectStep([1], `The harness inspects the ${FORMAT_NAMES[format]} credential of step 1.`, inspected(spec.checks(format), spec.what(format))),
      ],
      comments: ['Execute this test case once for each format named and each grant the Provider declares in its ICS (ICS-02, ICS-03).', ...(spec.comments ?? [])],
    }),
  );

export const definitions = [
  ...integrity({
    id: 'PP_WS_SM_IssuerIntegrity_001',
    formats: ['SD'],
    objective: () =>
      "Verify that the SD-JWT VC PID's issuer-signed JWT carries `typ` `dc+sd-jwt`, an ECCG agreed `alg`, and an `x5c` with the signer certificate and its intermediates but not the trust anchor, validating to the Provider's issuance anchor on `TL-PID`.",
    references: ['[ARF] Annex 2, PPNot_03', '[HAIP] section 6.1.1', '[SD-JWT VC] section 3.5', '[ARF] Annex 2, OIA_03'],
    checks: () => ['sd-jwt-typ', 'signer-algorithm', 'signer-chain'],
    what: () => 'The issuer-signed JWT header is as SD-JWT VC and HAIP require; the chain to `PP-T` is `issuer-trust` of `ISS` (step 1).',
    comments: ['OIDF `happy-flow` covers this objective partly (issuer catalogue section 7).'],
  }),
  ...integrity({
    id: 'PP_WS_SM_IssuerIntegrity_002',
    formats: ['MD'],
    objective: () =>
      "Verify that the mdoc PID's `IssuerAuth` is a COSE_Sign1 with an ECCG agreed `alg` and an `x5chain` validating to the Provider's issuance anchor, that `digestAlgorithm` is SHA-256 and that every value digest matches.",
    references: ['[ARF] Annex 2, PPNot_03', '[ISO/IEC 18013-5] section 9.1.2'],
    checks: () => ['signer-algorithm', 'signer-chain', 'mdoc-digest-algorithm'],
    what: () => '`IssuerAuth` is as ISO/IEC 18013-5 requires; the chain to `PP-T` is `issuer-trust` and the value digests `disclosures` of `ISS` (step 1).',
    comments: ['OIDF `happy-flow` covers this objective partly (issuer catalogue section 7).'],
  }),
  ...integrity({
    id: 'PP_WS_SM_IssuerIntegrity_003',
    formats: ['SD', 'MD'],
    objective: (f) => `Verify that the certificate that signs the ${FORMAT_NAMES[f]} PID follows the ETSI TS 119 412-6 profile of the Provider's category.`,
    references: ['[ARF] Annex 2, ISSU_68, ISSU_70, ISSU_71, ISSU_73', '[ETSI TS 119 412-6]'],
    checks: () => ['signer-profile'],
    what: (f) => `The ${FORMAT_NAMES[f]} signer certificate is the one the Test Registrar enrolled in the profile of a PID Provider.`,
  }),
  ...integrity({
    id: 'PP_WS_SM_IssuerIntegrity_004',
    formats: ['SD', 'MD'],
    objective: (f) => `Verify that the ${FORMAT_NAMES[f]} PID is not signed with the access certificate, and that the access certificate's key signs no credential.`,
    references: ['[ARF] Annex 2, ISSU_22', '[ARF] Annex 2, Reg_10'],
    checks: () => ['signer-not-access'],
    what: () => 'The credential signer is another certificate with another key than the access certificate the Test Registrar issued from `AC-A`.',
  }),
  ...integrity({
    id: 'PP_WS_SM_IssuerIntegrity_005',
    formats: ['SD'],
    objective: () => 'Verify that every claim the PID Rulebook allows is individually selectively disclosable in the SD-JWT VC PID (top level, nested members, array elements), and that `_sd_alg` is `sha-256`.',
    references: ['[ARF] Annex 2, PID_21', '[RFC9901] section 4.2.2'],
    checks: () => ['selective-disclosure'],
    what: () => 'Each PID claim, each member of a structured claim and each element of an array claim can be disclosed on its own.',
  }),
  ...integrity({
    id: 'PP_WS_SM_IssuerIntegrity_006',
    formats: ['SD', 'MD'],
    objective: (f) =>
      f === 'SD'
        ? 'Verify that every disclosure salt of the SD-JWT VC PID is unique within the credential, and record whether it reaches the RECOMMENDED 128 bits.'
        : 'Verify that the `random` of every IssuerSignedItem of the mdoc PID has at least 16 bytes and is unique within the credential.',
    references: ['[ARF] Annex 2, ISSU_35 (a)', '[RFC9901] section 9.3', '[ISO/IEC 18013-5] section 9.1.2.5 (not verified)'],
    checks: () => ['salt-entropy'],
    what: (f) =>
      f === 'SD'
        ? 'No salt repeats (RFC 9901 section 9.3: "A new salt MUST be chosen for each claim"); a salt below "The RECOMMENDED minimum length ... 128 bits" is recorded in the check detail, not failed.'
        : 'The `random` values are long and unique enough that no element can be guessed from its digest.',
    comments: [
      'OIDF `happy-flow` and `batch-issuance` cover this objective partly (issuer catalogue section 7).',
      'Spec review 2026-11-20 (issuer catalogue section 8.3): 128 bits is RECOMMENDED by RFC 9901 section 9.3, and ARF ISSU_35 is about uniqueness, so a shorter SD-JWT VC salt is no conformance failure. The ISO/IEC 18013-5 clause for the mdoc `random` was not available to the review.',
    ],
  }),
  ...integrity({
    id: 'PP_WS_SM_IssuerIntegrity_007',
    formats: ['SD', 'MD'],
    objective: (f) => `Verify that the signature algorithm of the ${FORMAT_NAMES[f]} PID is one of those its credential configuration advertises in the metadata.`,
    references: ['[OpenID4VCI] section 12.2.4'],
    checks: () => ['algorithm-advertised'],
    what: () => 'The credential is signed with an algorithm of `credential_signing_alg_values_supported`.',
    relevancy: relevancy.genericRequired,
  }),
];
