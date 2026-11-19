// RP_WS_SM_IssuerIntegrity: the authenticity of the presented credential. The Relying Party verifies the issuer's
// signature with an agreed algorithm and key, the type of the credential, its disclosures (SD-JWT VC) or value digests
// (mdoc), and the certificate path of the signer. `RP_WS_SM_IssuerIntegrity_035_UF` (signing certificate revoked by a
// CRL) is not written: the check is optional (catalogue ICS-16), and the harness serves no CRLs.
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
  ...(format === sdJwtVc ? ['[SD-JWT VC] section 2.5', '[HAIP] section 6.1.1'] : ['[ISO/IEC 18013-5] section 9.3.1']),
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
    references: ['[OpenID4VP] section 8.6, B.2.3'],
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
    objective: 'Verify that the Relying Party rejects a credential in mdoc format whose signing certificate is not a document signer certificate.',
    references: ['[ISO/IEC 18013-5] section 9.3.1, Annex B'],
    steps: [rejected('mdoc.ds-no-eku')],
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
];
