// RP_WS_SM_IssuerIntegrity: the authenticity of the presented credential. The Relying Party verifies the issuer's
// signature with an agreed algorithm and key, the type of the credential, its disclosures (SD-JWT VC) or value digests
// (mdoc), and the certificate path of the signer. `RP_WS_SM_IssuerIntegrity_035_UF` (signing certificate revoked by a
// CRL) is not written: the check is optional (catalogue ICS-16), and the harness serves no CRLs. `_016_UF` to `_018_UF`,
// `_029_UF` and `_038_UF` to `_042_UF` come from the negative vectors of issue 10.
import {
  acc,
  comments,
  defineTestCase,
  type FaultId,
  type FormatWording,
  faultInfo,
  formats,
  PID,
  pid,
  policyCheck,
  positiveControlOf,
  preconditions,
  presentation,
  presentationStep,
  type Relevancy,
  rej,
  relevancy,
  scenario,
  type StepDefinition,
  step,
  testCaseId,
} from '@rp-conformance/core';
import { oidf } from './binding';

const sdJwtVc = formats.sdJwtVc;
const mdoc = formats.mdoc;

const SD_JWT = ['[RFC9901] section 7.1', '[SD-JWT VC] section 2.5'];
const MSO = ['[ISO/IEC 18013-5] section 9.1.2, 9.3.1'];

interface IssuerIntegrityCase {
  number: number;
  variant?: 'a' | 'b';
  format: FormatWording;
  unhappyFlow?: boolean;
  objective: string;
  references: string[];
  relevancy?: Relevancy;
  steps: StepDefinition[];
  preconditions?: string[];
  comments?: string[];
}

const issuerIntegrity = (testCase: IssuerIntegrityCase) =>
  defineTestCase({
    id: testCaseId('WS', 'SM', 'IssuerIntegrity', testCase.number, testCase.variant ?? '', testCase.unhappyFlow ?? true),
    objective: testCase.objective,
    references: [...testCase.references, '[CIR 2024/2982 amended] Annex II'],
    profile: [testCase.format.profile],
    relevancy: testCase.relevancy ?? relevancy.genericRequired,
    technology: [testCase.format.technology],
    preconditions: [...preconditions.base, preconditions.control(positiveControlOf(testCase.format)), ...(testCase.preconditions ?? [])],
    control: positiveControlOf(testCase.format),
    steps: testCase.steps,
    comments: [...(testCase.comments ?? []), comments.flow],
  });

/** A presentation of `default_credential_pid` with a credential fault, rejected. */
const rejected = (fault: FaultId): StepDefinition => step({ ...presentationStep.credentialFault(fault), expect: rej() });

/** The fault of a path objective in the format of the test case: `credential.<name>` or `mdoc.<name>`. */
const faultOf = (format: FormatWording, name: string) => `${format === sdJwtVc ? 'credential' : 'mdoc'}.${name}` as FaultId;

/** A valid PID of `PP-I`, whose signing certificate is issued by its intermediate CA. */
const validOfPpI = (format: FormatWording) =>
  step({
    ...presentationStep.credentialVariant('it is issued by `PP-I`, whose signing certificate is issued by its intermediate CA `CA-PP-I-INT`', {
      credential: pid.of(format.credentialFormat, { issuer: 'PP-I' }),
    }),
    expect: acc({ credential: `${PID} issued by \`PP-I\`` }),
  });

const pathReferences = (format: FormatWording) => [
  '[RFC5280] section 6.1',
  // RFC 7515 section 4.1.6: "The recipient MUST validate the certificate chain according to RFC 5280" binds the `x5c`
  // of the SD-JWT VC to RFC 5280. The ISO/IEC 18013-5 clause was not available to the spec review of 2026-11-20.
  ...(format === sdJwtVc ? ['[RFC7515] section 4.1.6', '[SD-JWT VC] section 2.5', '[HAIP] section 6.1.1'] : ['[ISO/IEC 18013-5] section 9.3.1 (not verified)']),
];

/** The objectives of the certificate path, for both formats (IssuerIntegrity_030 to _037). */
const pathCases = (format: FormatWording) => {
  const name = format.name;
  const of = (number: number, objective: string, steps: StepDefinition[], extra: Partial<IssuerIntegrityCase> = {}) =>
    issuerIntegrity({ number, variant: format.letter, format, objective, references: pathReferences(format), steps, ...extra });
  const intermediateComment =
    'Step 1 shows that the Relying Party accepts a PID whose signing certificate is issued by an intermediate CA under a listed anchor, so the defect of the intermediate CA is the only difference in step 2.';
  return [
    of(30, `Verify that the Relying Party rejects a credential in ${name} format whose signing certificate has expired.`, [rejected(faultOf(format, 'signer-expired'))], {
      references: [...pathReferences(format), '[RFC5280] section 6.1.3'],
    }),
    of(31, `Verify that the Relying Party rejects a credential in ${name} format whose signing certificate is not yet valid.`, [
      rejected(faultOf(format, 'signer-not-yet-valid')),
    ]),
    of(32, `Verify that the Relying Party rejects a credential in ${name} format whose signing certificate is issued by an expired intermediate CA.`, [
      validOfPpI(format),
      rejected(faultOf(format, 'intermediate-expired')),
    ], { comments: [intermediateComment] }),
    of(33, `Verify that the Relying Party rejects a credential in ${name} format whose certificate chain lacks the intermediate CA between the signing certificate and the anchor.`, [
      validOfPpI(format),
      rejected(faultOf(format, 'intermediate-missing')),
    ], { comments: [intermediateComment] }),
    of(34, `Verify that the Relying Party rejects a credential in ${name} format whose signing certificate is issued by a certificate that is not a CA certificate.`, [
      validOfPpI(format),
      rejected(faultOf(format, 'issuer-not-ca')),
    ], { references: [...pathReferences(format), '[RFC5280] section 4.2.1.9'], comments: [intermediateComment] }),
    of(36, `Verify that the Relying Party rejects a credential in ${name} format signed with a key of a type or size outside the agreed cryptographic mechanisms.`, [
      rejected(faultOf(format, 'key-p192')),
      rejected(faultOf(format, 'key-rsa1024')),
    ], { relevancy: relevancy.specificRequired, references: [...pathReferences(format), '[ECCG ACM]', '[ARF] Annex 2, OIA_03'] }),
    of(37, `Verify that the Relying Party rejects a credential in ${name} format whose signing certificate carries an unknown extension marked critical.`, [
      rejected(faultOf(format, 'critical-extension')),
    ], { references: [...pathReferences(format), '[RFC5280] section 4.2'] }),
  ];
};

/** ICS RP.P.13: the Relying Party rejects a signing certificate that does not name `iss`. */
const namesIssuer = (fault: FaultId): StepDefinition =>
  step({
    ...presentationStep.credentialFault(fault),
    expect: policyCheck(
      'RP.P.13',
      'rejects a credential in SD-JWT VC format whose signing certificate does not name its `iss` by a `uniformResourceIdentifier` SAN equal to `iss` or, when the certificate has no URI SAN, by a `dNSName` SAN equal to the host of `iss`, in ASCII and lower case and with the port only when it is not the default port of the scheme, as a URL parser gives it',
    ),
  });

/** The test cases of the negative vectors of issue 10 that had no row. */
function issue10Cases() {
  const namesIssuerReferences = ['[SD-JWT VC] section 2.5, 6.2', '[RFC5280] section 4.2.1.6'];
  const namesIssuerComment =
    "[SD-JWT VC] section 2.5 makes the Issuer the subject of the end-entity certificate and requires the SD-JWT VC to be rejected when the key cannot be validated as the Issuer's, but no sentence of [SD-JWT VC] says how `iss` is compared with that certificate. Whether the Relying Party checks it is declared in ICS RP.P.13. A certificate names `iss` by a URI subject alternative name equal to it, or, when it names no URI, by a DNS name equal to the host of `iss`, in ASCII and lower case and with the port only when it is not the default port of the scheme, as a URL parser gives it.";
  return [
    issuerIntegrity({
      number: 16,
      format: sdJwtVc,
      objective: 'Verify that the Relying Party rejects a credential in SD-JWT VC format whose Issuer-signed JWT marks as critical a header parameter that the Relying Party does not understand.',
      references: ['[RFC7515] section 4.1.11', ...SD_JWT],
      steps: [rejected('credential.crit-unknown')],
      comments: ['`IssuerIntegrity_037_UF` covers an unknown critical extension of the signing certificate; this test case covers the `crit` header parameter of the JWS.'],
    }),
    issuerIntegrity({
      number: 17,
      format: sdJwtVc,
      objective:
        'Record whether the Relying Party accepts a credential in SD-JWT VC format whose `exp` claim is in a disclosure instead of the Issuer-signed JWT.',
      references: ['[SD-JWT VC] section 2.2.2.2', '[RFC9901] section 9.7'],
      relevancy: relevancy.genericOptional,
      steps: [
        step({
          ...presentationStep.credentialFault('credential.exp-disclosed'),
          expect: { codes: ['INFO'], text: 'Whether the Relying Party accepts or rejects the presentation is recorded; HTTP 5xx fails.' },
        }),
      ],
      comments: [
        'Informational (catalogue section 8.4): [SD-JWT VC] section 2.2.2.2 forbids the Issuer to put `exp` in a disclosure, and no sentence of [SD-JWT VC] or [RFC9901] requires the Relying Party to refuse the credential. [RFC9901] section 9.7 requires that Verifiers "ensure that all claims they deem necessary for checking the validity of an SD-JWT in the given context are present (or disclosed, respectively)".',
      ],
    }),
    issuerIntegrity({
      number: 18,
      format: sdJwtVc,
      objective:
        'Record whether the Relying Party accepts a credential in SD-JWT VC format whose `iss` claim is in a disclosure instead of the Issuer-signed JWT.',
      references: ['[SD-JWT VC] section 2.2.2.2', '[RFC9901] section 9.7'],
      relevancy: relevancy.genericOptional,
      steps: [
        step({
          ...presentationStep.credentialFault('credential.iss-disclosed'),
          expect: { codes: ['INFO'], text: 'Whether the Relying Party accepts or rejects the presentation is recorded; HTTP 5xx fails.' },
        }),
      ],
      comments: [
        'Informational (catalogue section 8.4): [SD-JWT VC] section 2.2.2.2 forbids the Issuer to put `iss` in a disclosure, and no sentence of [SD-JWT VC] or [RFC9901] requires the Relying Party to refuse the credential. [RFC9901] section 9.7 requires that Verifiers "ensure that all claims they deem necessary for checking the validity of an SD-JWT in the given context are present (or disclosed, respectively)".',
      ],
    }),
    issuerIntegrity({
      number: 29,
      format: mdoc,
      objective: 'Record whether the Relying Party accepts a credential in mdoc format whose IssuerAuth lists in `crit` a header parameter that the Relying Party does not understand.',
      references: ['[RFC9052] section 3.1', '[ISO/IEC 18013-5] section 9.1.2 (not verified)'],
      relevancy: relevancy.genericOptional,
      steps: [
        step({
          ...presentationStep.credentialFault('mdoc.issuer-auth-crit-unknown'),
          expect: { codes: ['INFO'], text: 'Whether the Relying Party accepts or rejects the presentation is recorded; HTTP 5xx fails.' },
        }),
      ],
      comments: [
        'Informational (catalogue section 8.4): [RFC9052] section 3.1 says that `crit` lists the header parameters an application processing the message "is required to understand", but no sentence of [RFC9052] says what a recipient does with a listed parameter it does not understand; the one fatal error it names, a listed label whose header parameter is not in the protected bucket, does not arise here. [ISO/IEC 18013-5] was not verified.',
      ],
    }),
    issuerIntegrity({
      number: 38,
      format: sdJwtVc,
      relevancy: relevancy.genericOptional,
      objective:
        "Verify that the Relying Party handles a credential in SD-JWT VC format whose signing certificate, issued under the right anchor, names another issuer's URI instead of the credential's `iss`, as it declares.",
      references: namesIssuerReferences,
      steps: [namesIssuer('credential.signer-names-other-issuer')],
      comments: [namesIssuerComment],
    }),
    issuerIntegrity({
      number: 39,
      format: sdJwtVc,
      relevancy: relevancy.genericOptional,
      objective:
        "Verify that the Relying Party handles a credential in SD-JWT VC format whose signing certificate, issued under the right anchor, names only the DNS name of another host instead of the credential's `iss` or its host, as it declares.",
      references: namesIssuerReferences,
      steps: [namesIssuer('credential.signer-names-other-host')],
      comments: [namesIssuerComment],
    }),
    issuerIntegrity({
      number: 40,
      format: sdJwtVc,
      relevancy: relevancy.genericOptional,
      objective:
        "Verify that the Relying Party handles a credential in SD-JWT VC format whose signing certificate, issued under the right anchor, names another issuer's URI and the host of the credential's `iss`, as it declares: the URI decides, not the host.",
      references: namesIssuerReferences,
      steps: [namesIssuer('credential.signer-uri-beats-host')],
      comments: [namesIssuerComment],
    }),
    issuerIntegrity({
      number: 41,
      format: mdoc,
      relevancy: relevancy.genericOptional,
      objective:
        "Verify that the Relying Party handles a credential in mdoc format whose IssuerAuth declares `ES384` (-35) and is signed with SHA-384 by the document signer's P-256 key, as it declares.",
      references: ['[RFC9053] section 2.1', '[RFC9864] section 2.1, 4.2.2, 4.4, 7', '[ISO/IEC 18013-5] section 9.1.2 (not verified)'],
      steps: [
        step({
          ...presentationStep.credentialFault('mdoc.issuer-auth-es384-p256'),
          expect: policyCheck('RP.P.14', 'rejects a credential in mdoc format whose IssuerAuth declares `ES384` (-35) over a P-256 document signer key'),
        }),
      ],
      comments: [
        '[RFC9053] section 2.1 only suggests that SHA-384 be used with P-384, and [RFC9864] section 2.1 calls `ES384` polymorphic, since it does not name a curve; section 4.2.2 deprecates it, which section 4.4 defines as a SHOULD for new deployments. [RFC9864] section 7 says "A cryptographic key MUST be used with only a single algorithm unless the use of the same key with different algorithms is proven secure.", and the document signer key also signs `ES256` in `RP_WS_IA_MainInteraction_001b`. To hold a key to one algorithm, section 7 recommends the algorithm parameter of a JSON Web Key or a COSE Key "unless there exists some other mechanism for ensuring that the key is used as intended", and names no other mechanism for a signing key; this key comes in an X.509 certificate in `x5chain`, which is neither, so section 7 does not tell the Relying Party which one algorithm the key has. This test case reads the MUST as one the Relying Party can apply only through such a mechanism. [ISO/IEC 18013-5] was not verified, so ICS RP.P.14 declares whether the Relying Party refuses `ES384` over a P-256 key. `IssuerIntegrity_042_UF` presents a signature made the same way under the fully specified `ESP384`.',
      ],
    }),
    issuerIntegrity({
      number: 42,
      format: mdoc,
      objective:
        "Verify that the Relying Party rejects a credential in mdoc format whose IssuerAuth declares `ESP384` (-51), which is ECDSA on P-384 with SHA-384, and is signed by the document signer's P-256 key.",
      references: ['[RFC9864] section 2.1', '[RFC9360] section 5', '[ISO/IEC 18013-5] section 9.1.2 (not verified)'],
      steps: [rejected('mdoc.issuer-auth-esp384-p256')],
      comments: [
        '[RFC9864] section 2.1 defines `ESP384` as ECDSA using the P-384 curve and SHA-384, and [RFC9360] section 5 requires the key in a certificate to be checked against the algorithm to be used, so the P-256 key of the document signer does not fit it.',
      ],
    }),
  ];
}

export const definitions = [
  issuerIntegrity({
    number: 1,
    format: sdJwtVc,
    objective: 'Verify that the Relying Party rejects a credential in SD-JWT VC format whose issuer signature is invalid.',
    references: SD_JWT,
    steps: [rejected('credential.signature-bitflip'), rejected('credential.signature-der')],
    comments: [oidf('invalid-credential-signature')],
  }),
  issuerIntegrity({
    number: 2,
    format: sdJwtVc,
    objective: 'Verify that the Relying Party rejects a credential in SD-JWT VC format whose Issuer-signed JWT is unsecured or protected with a symmetric algorithm.',
    references: [...SD_JWT, '[RFC8725] section 3.1, 3.2'],
    steps: [rejected('credential.alg-none'), rejected('credential.alg-hs256')],
  }),
  issuerIntegrity({
    number: 3,
    format: sdJwtVc,
    relevancy: relevancy.specificRequired,
    objective: 'Verify that the Relying Party rejects a credential in SD-JWT VC format whose issuer signature uses an algorithm outside the agreed cryptographic mechanisms.',
    references: [...SD_JWT, '[ECCG ACM]', '[HAIP] section 7', '[ARF] Annex 2, OIA_03'],
    steps: [rejected('credential.es256k')],
  }),
  issuerIntegrity({
    number: 4,
    format: sdJwtVc,
    objective: 'Verify that the Relying Party rejects a credential in SD-JWT VC format without the certificate chain of its signer.',
    references: [...SD_JWT, '[HAIP] section 6.1.1'],
    steps: [rejected('credential.no-x5c')],
  }),
  issuerIntegrity({
    number: 5,
    format: sdJwtVc,
    objective: 'Verify that the Relying Party rejects a credential in SD-JWT VC format whose certificate chain only validates to a root it carries itself.',
    references: [...SD_JWT, '[HAIP] section 6.1.1', '[ARF] Annex 2, OIA_12'],
    steps: [rejected('credential.embedded-root')],
  }),
  issuerIntegrity({
    number: 6,
    format: sdJwtVc,
    objective: 'Verify that the Relying Party rejects a credential in SD-JWT VC format signed with a self-signed certificate.',
    references: [...SD_JWT, '[HAIP] section 6.1.1'],
    steps: [rejected('credential.self-signed')],
  }),
  issuerIntegrity({
    number: 7,
    format: sdJwtVc,
    relevancy: relevancy.specificRequired,
    objective: 'Verify that the Relying Party rejects a credential in SD-JWT VC format whose type header is not `dc+sd-jwt`.',
    references: ['[SD-JWT VC] section 2.2.1', '[HAIP] section 5.3.2'],
    steps: [rejected('credential.typ-missing'), rejected('credential.typ-jwt'), rejected('credential.typ-vc-sd-jwt')],
    comments: [
      '[SD-JWT VC] section 2.2.1 recommends accepting `vc+sd-jwt` during a transition period. The EUDI profile of this test suite takes no transition period, so step 3 expects a rejection.',
    ],
  }),
  issuerIntegrity({
    number: 8,
    format: sdJwtVc,
    objective: 'Verify that the Relying Party rejects a credential in SD-JWT VC format with a disclosure whose digest the Issuer-signed JWT does not contain.',
    references: ['[RFC9901] section 7.1'],
    steps: [rejected('credential.disclosure-foreign'), rejected('credential.disclosure-modified')],
  }),
  issuerIntegrity({
    number: 9,
    format: sdJwtVc,
    objective: 'Verify that the Relying Party rejects a credential in SD-JWT VC format in which a digest occurs more than once.',
    references: ['[RFC9901] section 7.1'],
    steps: [rejected('credential.disclosure-duplicate'), rejected('credential.digest-duplicate')],
  }),
  issuerIntegrity({
    number: 10,
    format: sdJwtVc,
    objective:
      'Verify that the Relying Party rejects a credential in SD-JWT VC format with a disclosure whose claim name is reserved or already present at its level.',
    references: ['[RFC9901] section 4.2.1, 7.1'],
    steps: [rejected('credential.disclosure-name-sd'), rejected('credential.disclosure-name-ellipsis'), rejected('credential.disclosure-name-present')],
  }),
  issuerIntegrity({
    number: 11,
    format: sdJwtVc,
    objective: 'Verify that the Relying Party rejects a credential in SD-JWT VC format with a disclosure that has the wrong number of elements for where it is referenced.',
    references: ['[RFC9901] section 4.2.1, 4.2.2, 7.1'],
    steps: [rejected('credential.disclosure-two-elements'), rejected('credential.disclosure-array-three-elements'), rejected('credential.disclosure-four-elements')],
  }),
  issuerIntegrity({
    number: 12,
    format: sdJwtVc,
    objective: 'Verify that the Relying Party rejects a credential in SD-JWT VC format whose digests use an insecure hash algorithm.',
    references: ['[RFC9901] section 4.1.1, 7.1', '[HAIP] section 8'],
    steps: [rejected('credential.sd-alg-md5'), rejected('credential.sd-alg-sha1')],
  }),
  issuerIntegrity({
    number: 13,
    format: sdJwtVc,
    objective: 'Verify that the Relying Party rejects a credential in SD-JWT VC format whose type was not requested.',
    references: ['[OpenID4VP] section 8.6, 14.9, B.3.5'],
    steps: [rejected('credential.vct-other')],
    comments: [oidf('wrong-vct')],
  }),
  issuerIntegrity({
    number: 14,
    format: sdJwtVc,
    unhappyFlow: false,
    objective: 'Verify that the Relying Party accepts a credential in SD-JWT VC format that contains decoy digests.',
    references: ['[RFC9901] section 4.2.5, 7.1'],
    steps: [step({ ...presentationStep.credentialFault('credential.decoys'), expect: acc({ credential: PID }) })],
  }),
  issuerIntegrity({
    number: 15,
    format: sdJwtVc,
    unhappyFlow: false,
    objective: 'Verify that the Relying Party resolves the recursive disclosures of a structured claim of a credential in SD-JWT VC format.',
    references: ['[RFC9901] section 4.2.6, 7.1', '[PID rulebook]'],
    preconditions: [preconditions.placeOfBirth],
    steps: [
      step({
        text: scenario.credentialVariant(faultInfo('credential.recursive-disclosures').text),
        run: presentation({ query: 'default_query_pid_place_of_birth', credential: pid.sdJwtVc({ faults: ['credential.recursive-disclosures'] }) }),
        expect: acc({ credential: PID }),
      }),
    ],
  }),
  issuerIntegrity({
    number: 20,
    format: mdoc,
    objective: 'Verify that the Relying Party rejects a credential in mdoc format whose issuer signature is invalid.',
    references: MSO,
    steps: [rejected('mdoc.signature-bitflip'), rejected('mdoc.signature-der')],
  }),
  issuerIntegrity({
    number: 21,
    format: mdoc,
    objective: 'Verify that the Relying Party rejects a credential in mdoc format with a data element whose digest does not match the MSO.',
    references: MSO,
    steps: [rejected('mdoc.element-value-changed'), rejected('mdoc.digest-reencoded-item'), rejected('mdoc.digest-truncated')],
  }),
  issuerIntegrity({
    number: 22,
    format: mdoc,
    objective: 'Verify that the Relying Party rejects a credential in mdoc format with a data element whose digest identifier the MSO does not contain.',
    references: MSO,
    steps: [rejected('mdoc.digest-id-unknown')],
  }),
  issuerIntegrity({
    number: 23,
    format: mdoc,
    objective: 'Verify that the Relying Party rejects a credential in mdoc format whose MSO is for a document type other than that of the document.',
    references: MSO,
    steps: [rejected('mdoc.mso-doctype-other')],
  }),
  issuerIntegrity({
    number: 24,
    format: mdoc,
    objective: 'Verify that the Relying Party rejects a credential in mdoc format whose value digests use an insecure hash algorithm.',
    references: [...MSO, '[HAIP] section 8'],
    steps: [rejected('mdoc.digest-sha1')],
  }),
  issuerIntegrity({
    number: 25,
    format: mdoc,
    objective: 'Verify that the Relying Party rejects a credential in mdoc format of a document type that was not requested.',
    references: ['[OpenID4VP] section 8.6, 14.9, B.2.3'],
    steps: [rejected('mdoc.doctype-other')],
  }),
  issuerIntegrity({
    number: 26,
    format: mdoc,
    objective: 'Verify that the Relying Party rejects a credential in mdoc format whose certificate chain only validates to a root it carries itself.',
    references: [...MSO, '[ARF] Annex 2, OIA_12'],
    steps: [rejected('mdoc.embedded-root')],
  }),
  issuerIntegrity({
    number: 27,
    format: mdoc,
    objective: 'Record whether the Relying Party accepts a credential in mdoc format whose signing certificate, under the right anchor, is not an ISO/IEC 18013-5 document signer certificate (no extended key usage `1.0.18013.5.1.2`).',
    references: ['[ISO/IEC 18013-5] Annex B (not verified)', '[ETSI TS 119 412-6] clause 4'],
    relevancy: relevancy.genericOptional,
    steps: [
      step({
        ...presentationStep.credentialFault('mdoc.ds-no-eku'),
        expect: { codes: ['INFO'], text: 'Whether the Relying Party accepts or rejects the presentation is recorded; HTTP 5xx fails.' },
      }),
    ],
    comments: [
      'Informational since the spec review of 2026-11-20 (catalogue section 8.3): ETSI TS 119 412-6 clause 4, the certificate profile of PID Providers, requires no extended key usage (it allows key usage type C "Due to the requirements of ISO/IEC 18013-5"), and the ISO/IEC 18013-5 Annex B profile of the document signer was not available to the review. The test certificate is a plain end-entity certificate, so it differs from a document signer in more than the extended key usage.',
    ],
  }),
  issuerIntegrity({
    number: 28,
    format: mdoc,
    objective: 'Verify that the Relying Party rejects a credential in mdoc format whose MSO was signed outside the validity period of its document signer certificate.',
    references: MSO,
    steps: [rejected('mdoc.signed-after-ds-expiry')],
  }),
  ...pathCases(sdJwtVc),
  ...pathCases(mdoc),
  ...issue10Cases(),
];
