// RP_PP_SM_Revocation: validation of the Status List Tokens and identifier lists that PID Providers publish.
import {
  acc,
  all,
  comments,
  defineTestCase,
  type FaultId,
  type FormatWording,
  fetched,
  formats,
  ics,
  nostat,
  PID,
  pid,
  positiveControlOf,
  preconditions,
  presentation,
  presentationStep,
  QUERY_PID,
  rej,
  relevancy,
  scenario,
  type StepAction,
  statusListToken as statusListTokenSpec,
  step,
  technology,
  testCaseId,
} from '@rp-conformance/core';

const sdJwtVc = formats.sdJwtVc;
const mdoc = formats.mdoc;

const TOKEN_REFERENCES = {
  jwt: ['[Token Status List] section 5.1, 8.3', '[RFC7519] section 7.2'],
  cwt: ['[Token Status List] section 5.2, 8.3', '[RFC8392] section 7.2'],
};
const COMMON_REFERENCES = ['[ARF] Annex 2, PPNot_05, VCR_13, VCR_14', '[ETSI TS 119 602]', '[CIR 2024/2979 amended] Annex II'];
const referencesOf = (format: FormatWording, ...extra: string[]) => [
  ...(format === sdJwtVc ? TOKEN_REFERENCES.jwt : TOKEN_REFERENCES.cwt),
  ...extra,
  ...COMMON_REFERENCES,
];

/** `x5c` or `x5chain`. */
const x5 = (format: FormatWording) => (format === sdJwtVc ? '`x5c`' : '`x5chain`');
/** JWT or CWT. */
const tokenFormat = (format: FormatWording) => (format === sdJwtVc ? 'JWT' : 'CWT');

const NOSTAT_COMMENTS = [comments.nostat, comments.flow];

const validTokenDescription = (format: FormatWording) =>
  format === sdJwtVc
    ? 'with `typ` `statuslist+jwt`, a `sub` claim equal to the credential\'s status `uri`, an `iat` claim, an `exp` claim in the future and a `ttl` claim'
    : "with the type header (16) `application/statuslist+cwt`, a subject (2) equal to the credential's status `uri`, an issued at claim (6), an expiration time (4) in the future and a time to live (65534)";

const bareList = (format: FormatWording) =>
  `Perform a presentation for ${QUERY_PID} in which the Conformance Wallet presents ${PID} in a valid Authorization Response, while the Test Status Provider serves, for the status list referenced by the credential, the bare status list ${format === sdJwtVc ? 'JSON object' : 'CBOR map'} (\`bits\`, \`lst\`) instead of a Status List Token.`;

const missingClaims = (format: FormatWording) =>
  format === sdJwtVc
    ? [
        'its payload has no `sub` claim',
        'its payload has no `iat` claim',
        'its payload has no `status_list` claim',
        'its `status_list` claim has no `bits` member',
        'its `status_list` claim has no `lst` member',
      ]
    : [
        'its claims set has no subject (2)',
        'its claims set has no issued at claim (6)',
        'its claims set has no status list claim (65533)',
        'its status list claim has no `bits` entry',
        'its status list claim has no `lst` entry',
      ];

const corruptLists = (format: FormatWording) =>
  format === sdJwtVc
    ? [
        'the `lst` member of its `status_list` claim is not valid base64url',
        'the `lst` member of its `status_list` claim decodes to bytes that are not valid ZLIB data',
      ]
    : ['the `lst` entry of its status list claim is not valid ZLIB data'];

const algorithms = (format: FormatWording) =>
  format === sdJwtVc
    ? [
        'it is signed with `ES256K` (curve secp256k1)',
        'it is protected with `HS256`, keyed with the encoded public key of the certificate in its `x5c` header',
      ]
    : [
        'it is signed with `ES256K` (curve secp256k1)',
        'it is protected with a `COSE_Mac0` structure using HMAC 256/256, keyed with the encoded public key of the certificate in its `x5chain` header',
      ];

const bitsSteps = (executable: boolean) =>
  ([1, 2, 4, 8] as const).flatMap((bits) => {
    const index = 16 / bits - 1;
    const common = `Perform a presentation for ${QUERY_PID} in which the Conformance Wallet presents ${PID}, issued with status index ${index}, in a valid Authorization Response, while the Test Status Provider serves a valid Status List Token for it with \`bits\` set to ${bits}, in which `;
    const run = (status: number, others: number) =>
      executable ? { run: withStatusList(statusListTokenSpec.jwt({ bits, index, status, others })) } : {};
    return [
      step({ text: `${common}the entry at index ${index} holds 0x01 and every other entry holds 0x00.`, ...run(1, 0), expect: rej() }),
      step({ text: `${common}the entry at index ${index} holds 0x00 and every other entry holds 0x01.`, ...run(0, 1), expect: acc() }),
    ];
  });

/** A presentation of `default_credential_pid` while the Test Status Provider serves `statusList` for it. */
const withStatusList = (statusList: ReturnType<typeof statusListTokenSpec.jwt>, credential = pid.sdJwtVc()): StepAction =>
  presentation({ query: 'default_query_pid', credential, statusList });

const statusListToken = (format: FormatWording) => {
  const name = tokenFormat(format);
  const base = {
    profile: [format.profile, ics.checksPidRevocation],
    technology: [format.technology, format.statusListTechnology],
    preconditions: [...preconditions.base, preconditions.control(positiveControlOf(format)), preconditions.freshStatusList],
    control: positiveControlOf(format),
  };
  const id = (number: number, unhappyFlow = true) => testCaseId('PP', 'SM', 'Revocation', number, format.letter, unhappyFlow);
  const executable = format === sdJwtVc;
  const rejected = (differences: string[]) =>
    differences.map((difference) => step({ text: scenario.statusListToken(difference), expect: nostat() }));
  /** Status List Token faults: executable in JWT format; the CWT wording stays text only until Phase 2. */
  const faulty = (faults: FaultId[], cwtDifferences: string[]) =>
    executable ? faults.map((fault) => step({ ...presentationStep.statusListFault(fault), expect: nostat() })) : rejected(cwtDifferences);
  const valid = executable ? { run: withStatusList(statusListTokenSpec.jwt()) } : {};
  return [
    defineTestCase({
      id: id(1, false),
      ...base,
      relevancy: relevancy.genericRequired,
      objective: `Verify that the Relying Party evaluates a valid Status List Token in ${name} format and accepts a PID whose status is VALID.`,
      references: referencesOf(format, '[HAIP] section 6.1'),
      steps: [
        step({
          text: `Perform a presentation for ${QUERY_PID} in which the Conformance Wallet presents ${PID} in a valid Authorization Response, while the Test Status Provider serves, for the status list referenced by the credential, a Status List Token ${validTokenDescription(format)}, signed by a certificate under the revocation anchor of \`PP-A\`, that holds the value 0x00 at the credential's index.`,
          ...valid,
          expect: all(acc({ credential: PID }), fetched()),
        }),
      ],
      comments: [comments.flow],
    }),
    defineTestCase({
      id: id(2),
      ...base,
      relevancy: relevancy.genericRequired,
      objective: `Verify that the Relying Party does not use a Status List Token in ${name} format with an invalid signature.`,
      references: referencesOf(format),
      steps: faulty(['status-list.signature-bitflip'], ['one bit of its signature value is flipped']),
      comments: NOSTAT_COMMENTS,
    }),
    defineTestCase({
      id: id(3),
      ...base,
      relevancy: relevancy.genericRequired,
      objective: `Verify that the Relying Party does not use an unsigned Status List Token or a bare status list in place of a Status List Token in ${name} format.`,
      references: referencesOf(format),
      steps: [
        ...(format === sdJwtVc ? faulty(['status-list.alg-none'], []) : []),
        step({
          ...(executable ? presentationStep.statusListFault('status-list.bare-list', { text: bareList(format) }) : { text: bareList(format) }),
          expect: nostat(),
        }),
      ],
      comments: NOSTAT_COMMENTS,
    }),
    defineTestCase({
      id: id(4),
      ...base,
      relevancy: relevancy.genericRequired,
      objective: `Verify that the Relying Party does not use an expired Status List Token in ${name} format.`,
      references: referencesOf(format),
      steps: faulty(['status-list.exp-past'], ['its expiration time (4) is set to the current time minus `T_skew` minus one hour']),
      comments: NOSTAT_COMMENTS,
    }),
    defineTestCase({
      id: id(5),
      ...base,
      relevancy: relevancy.genericRequired,
      objective: `Verify that the Relying Party does not use a Status List Token in ${name} format whose subject differs from the status list URI in the credential.`,
      references: referencesOf(format),
      steps: faulty(['status-list.sub-other'], ['its subject (2) is the URI of a different status list']),
      comments: NOSTAT_COMMENTS,
    }),
    defineTestCase({
      id: id(6),
      ...base,
      relevancy: relevancy.genericRequired,
      objective: `Verify that the Relying Party does not use a Status List Token in ${name} format that declares the wrong type.`,
      references: referencesOf(format),
      steps: faulty(['status-list.typ-jwt'], ['its type header (16) is `application/cwt`']),
      comments: NOSTAT_COMMENTS,
    }),
    defineTestCase({
      id: id(7),
      ...base,
      relevancy: relevancy.genericRequired,
      objective: `Verify that the Relying Party does not use a Status List Token in ${name} format that lacks a required claim.`,
      references: referencesOf(format),
      steps: faulty(
        ['status-list.no-sub', 'status-list.no-iat', 'status-list.no-status-list', 'status-list.no-bits', 'status-list.no-lst'],
        missingClaims(format),
      ),
      comments: NOSTAT_COMMENTS,
    }),
    defineTestCase({
      id: id(8),
      ...base,
      relevancy: relevancy.genericRequired,
      objective: `Verify that the Relying Party does not use a Status List Token in ${name} format whose signer is not trusted.`,
      references: referencesOf(format, '[HAIP] section 6.1', '[Token Status List] section 11.3'),
      steps: faulty(
        ['status-list.signer-ca-x', 'status-list.no-x5c', 'status-list.signer-self-signed'],
        [
          `it is signed by a certificate issued by \`CA-X\`, with that certificate chain in ${x5(format)}`,
          `it carries no ${x5(format)} header, so its signer cannot be validated`,
          'it is signed by a self-signed certificate that is not part of `default_trust_configuration_rp`',
        ],
      ),
      comments: NOSTAT_COMMENTS,
    }),
    defineTestCase({
      id: id(9),
      ...base,
      relevancy: relevancy.specificRequired,
      objective: `Verify that the Relying Party does not use a Status List Token in ${name} format signed under a trusted anchor of another entity or another list.`,
      references: referencesOf(format, '[Token Status List] section 11.3'),
      steps: faulty(
        ['status-list.signer-pp-b-revocation', 'status-list.signer-wp-a-revocation', 'status-list.signer-ac-a'],
        [
          'it is signed by a certificate under the revocation anchor of `PP-B`',
          'it is signed by a certificate under the revocation anchor of the Wallet Provider `WP-A` in `TL-WP`',
          'it is signed by a certificate under the anchor of `AC-A` in `TL-AC`',
        ],
      ),
      comments: [
        '`default_trust_configuration_rp` defines that a status list is trusted only under the revocation anchor of the entity that issued the credential.',
        ...NOSTAT_COMMENTS,
      ],
    }),
    defineTestCase({
      id: id(10, false),
      ...base,
      relevancy: relevancy.specificRequired,
      objective: `Verify that the Relying Party uses a Status List Token in ${name} format signed under the revocation anchor of the entity that issued the credential.`,
      references: referencesOf(format, '[Token Status List] section 11.3'),
      steps: [
        step({
          text: `Perform a presentation for ${QUERY_PID} in which the Conformance Wallet presents ${PID} in a valid Authorization Response, while the Test Status Provider serves a valid Status List Token for it that holds the value 0x00 at the credential's index and is signed by a certificate under the revocation anchor \`CA-PP-A-REV\` of \`PP-A\`.`,
          ...valid,
          expect: all(acc({ credential: PID }), fetched()),
        }),
        step({
          text: `Perform a presentation for ${QUERY_PID} in which the Conformance Wallet presents a variant of ${PID} issued by \`PP-B\` in a valid Authorization Response, while the Test Status Provider serves a valid Status List Token for it that holds the value 0x00 at the credential's index and is signed with the same key and certificate as that credential.`,
          ...(executable
            ? { run: withStatusList(statusListTokenSpec.jwt({ signer: { entity: 'PP-B', key: 'issuance' } }), pid.sdJwtVc({ issuer: 'PP-B' })) }
            : {}),
          expect: all(acc(), fetched()),
        }),
      ],
      comments: [
        'In the second step the issuance CA of `PP-B` is also published under the revocation service of `PP-B`, which is how `default_trust_configuration_rp` represents an issuer that signs its status lists with its issuance key ([Token Status List] section 11.3).',
        comments.flow,
      ],
    }),
    defineTestCase({
      id: id(11),
      ...base,
      relevancy: relevancy.specificRequired,
      objective: `Verify that the Relying Party does not use a Status List Token in ${name} format whose signer chains only to the issuance anchor of the issuing entity, when that anchor is not published under the entity's revocation service.`,
      references: referencesOf(format, '[Token Status List] section 11.3'),
      steps: faulty(
        ['status-list.signer-credential-certificate', 'status-list.signer-other-issuance-certificate'],
        [
          'it is signed with the key and certificate that signed the presented credential',
          'it is signed by another certificate issued under the issuance CA `CA-PP-A` of `PP-A`',
        ],
      ),
      comments: [
        '`PP-A` publishes separate CAs for its issuance and revocation services, so its issuance CA is not a root of trust for its status lists.',
        ...NOSTAT_COMMENTS,
      ],
    }),
    defineTestCase({
      id: id(12),
      ...base,
      relevancy: relevancy.genericRequired,
      objective: `Verify that the Relying Party does not trust a root certificate embedded in the ${x5(format)} header of a Status List Token in ${name} format.`,
      references: referencesOf(format, '[HAIP] section 6.1'),
      steps: faulty(
        ['status-list.embedded-root'],
        [`its signer certificate chains to a self-signed root that ${x5(format)} includes and that is not part of \`default_trust_configuration_rp\``],
      ),
      comments: NOSTAT_COMMENTS,
    }),
    defineTestCase({
      id: id(13),
      ...base,
      relevancy: relevancy.genericRequired,
      objective: `Verify that the Relying Party does not use a Status List Token in ${name} format whose signer certificate is outside its validity period.`,
      references: referencesOf(format, '[RFC5280] section 6.1.3'),
      steps: faulty(['status-list.signer-expired', 'status-list.signer-not-yet-valid'], ['its signer certificate has expired', 'its signer certificate is not yet valid']),
      comments: NOSTAT_COMMENTS,
    }),
    defineTestCase({
      id: id(15),
      ...base,
      relevancy: relevancy.genericRequired,
      objective: `Verify that the Relying Party does not use a Status List Token in ${name} format whose compressed status list is corrupt.`,
      references: referencesOf(format, '[Token Status List] section 4.1, 11.1'),
      steps: faulty(['status-list.lst-not-base64url', 'status-list.lst-not-zlib'], corruptLists(format)),
      comments: NOSTAT_COMMENTS,
    }),
    defineTestCase({
      id: id(16),
      ...base,
      relevancy: relevancy.genericRequired,
      objective: `Verify that the Relying Party refuses a Status List Token in ${name} format whose status list decompresses to more than its declared maximum size, and stays available.`,
      references: referencesOf(format, '[Token Status List] section 4.1, 11.1'),
      steps: [
        ...faulty(
          ['status-list.decompression-bomb'],
          [
            'its `lst` value decompresses to more bytes than the maximum status list size the Relying Party declares, for example a ZLIB stream that inflates to 1 GiB of zero bytes',
          ],
        ),
        step({
          ...(executable
            ? presentationStep.valid({
                text: {
                  credential: `a newly issued ${PID}`,
                  extra: ', immediately after the previous step, while the status list referenced by that credential is valid and holds the value 0x00 at its index',
                },
              })
            : {
                text: scenario.valid({
                  credential: `a newly issued ${PID}`,
                  extra: ', immediately after the previous step, while the status list referenced by that credential is valid and holds the value 0x00 at its index',
                }),
              }),
          expect: acc(),
        }),
      ],
      comments: [
        'Every entry of the inflated list holds 0x00, so a Relying Party that processes the list without a size limit accepts the presentation in the first step.',
        ...NOSTAT_COMMENTS,
      ],
    }),
    defineTestCase({
      id: id(17),
      ...base,
      relevancy: relevancy.genericRequired,
      objective: `Verify that the Relying Party does not use a Status List Token in ${name} format with an unsupported number of bits per status.`,
      references: referencesOf(format, '[Token Status List] section 4.1'),
      steps: faulty(['status-list.bits-3'], ['the `bits` value of its status list is 3']),
      comments: NOSTAT_COMMENTS,
    }),
    defineTestCase({
      id: id(18, false),
      ...base,
      relevancy: relevancy.genericRequired,
      objective: `Verify that the Relying Party reads the status value at the credential's index correctly from a Status List Token in ${name} format, for every permitted number of bits per status.`,
      references: referencesOf(format, '[Token Status List] section 4.1'),
      steps: bitsSteps(executable),
      comments: [
        "Each index is the last entry of the second byte of the status list, so a Relying Party that reads the bits in the wrong order within a byte, or computes the byte offset incorrectly, reads a neighbouring entry. Every step uses a newly issued credential.",
        comments.flow,
      ],
    }),
    defineTestCase({
      id: id(19),
      ...base,
      relevancy: relevancy.specificRequired,
      objective: `Verify that the Relying Party does not use a Status List Token in ${name} format protected with an algorithm outside the agreed cryptographic mechanisms.`,
      references: referencesOf(format, '[ECCG ACM]', '[HAIP] section 6.1, 7', '[RFC8725] section 3.1'),
      steps: faulty(['status-list.es256k', 'status-list.hs256-public-key'], algorithms(format)),
      comments: NOSTAT_COMMENTS,
    }),
  ];
};

const identifierList = defineTestCase({
  id: testCaseId('PP', 'SM', 'Revocation', 30, '', true),
  relevancy: relevancy.specificRequired,
  objective:
    'Verify that the Relying Party does not use an identifier list in CWT format that is badly signed, expired or signed by an untrusted signer.',
  references: [
    '[ISO/IEC 18013-5 ed2]',
    '[RFC8392] section 7.2',
    '[ARF] Annex 2, PPNot_05, VCR_11, VCR_12, VCR_14',
    '[ETSI TS 119 602]',
    '[CIR 2024/2979 amended] Annex II',
  ],
  profile: [mdoc.profile, ics.checksPidRevocation],
  technology: [mdoc.technology, technology.identifierListCwt],
  preconditions: [
    ...preconditions.base,
    preconditions.control(positiveControlOf(mdoc)),
    preconditions.freshStatusList,
    preconditions.identifierList,
    preconditions.identifierListOmits,
  ],
  control: positiveControlOf(mdoc),
  steps: [
    'one bit of the signature value of the referenced identifier list is flipped',
    'the expiration time (4) of the referenced identifier list lies `T_skew` plus one hour in the past',
    'the referenced identifier list is signed by a certificate issued by `CA-X`',
  ].map((difference) =>
    step({
      text: `Perform a presentation for ${QUERY_PID} in which the Conformance Wallet presents ${PID} in a valid Authorization Response, while ${difference}.`,
      expect: nostat(),
    }),
  ),
  comments: NOSTAT_COMMENTS,
});

export const definitions = [...statusListToken(sdJwtVc), ...statusListToken(mdoc), identifierList];
