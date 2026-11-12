// RP_WS_SM_TrustMechanisms: the trust anchor of the credential and its category.
import {
  acc,
  attestation,
  type CredentialCategory,
  comments,
  type CredentialSpec,
  credentials,
  type DefaultQueryId,
  defineTestCase,
  type FormatWording,
  formats,
  ics,
  type IcsCondition,
  listRetrieved,
  PID,
  pid,
  type PidOptions,
  pidQueryOf,
  positiveControlOf,
  preconditions,
  presentation,
  presentationStep,
  queries,
  queryOf,
  rej,
  relevancy,
  scenario,
  step,
  testCaseId,
} from '@rp-conformance/core';

const sdJwtVc = formats.sdJwtVc;
const mdoc = formats.mdoc;

const TRUST_REFERENCES = {
  sdJwtVc: ['[SD-JWT VC] section 2.5', '[HAIP] section 6.1.1', '[RFC5280] section 6.1'],
  mdoc: ['[ISO/IEC 18013-5] section 9.3.1', '[RFC5280] section 6.1'],
};
const trustReferencesOf = (format: FormatWording) => (format === sdJwtVc ? TRUST_REFERENCES.sdJwtVc : TRUST_REFERENCES.mdoc);
const referencesOf = (format: FormatWording, arf: string, lists = ['[ETSI TS 119 602]']) => [
  `[ARF] Annex 2, ${arf}`,
  ...trustReferencesOf(format),
  ...lists,
];

const WAIT = 'Wait until the Relying Party has retrieved it, at most `T_refresh`.';

const trustMechanisms = (format: FormatWording) => {
  const id = (number: number, unhappyFlow = true) => testCaseId('WS', 'SM', 'TrustMechanisms', number, format.letter, unhappyFlow);
  const base = (profile: IcsCondition[] = []) => ({
    profile: [format.profile, ...profile],
    relevancy: relevancy.specificRequired,
    technology: [format.technology],
    preconditions: [...preconditions.base, preconditions.control(positiveControlOf(format))],
    control: positiveControlOf(format),
  });
  /** `default_credential_pid` in the format of the test case, issued by `issuer` or signed under another anchor. */
  const pidOf = (options: PidOptions = {}) => pid.of(format.credentialFormat, options);
  /** A PID that differs only in its issuer or signer. */
  const variant = (difference: string, credential: CredentialSpec, query: DefaultQueryId = pidQueryOf(format.credentialFormat)) =>
    presentationStep.credentialVariant(difference, { credential, query });
  /** `default_credential_A` of a category in the format of the test case, presented for the category's default query. */
  const attestationOf = (category: Exclude<CredentialCategory, 'pid'>, issuer?: string) =>
    presentation({ query: queryOf(category, format.credentialFormat), credential: attestation.of(category, format.credentialFormat, { issuer }) });
  /** A variant of the category's default credential that differs only in its issuer, which is not trusted for it. */
  const issuedBy = (
    difference: string,
    options: { credential: string; query: string },
    category: Exclude<CredentialCategory, 'pid'>,
    issuer: string,
  ) => step({ text: scenario.credentialVariant(difference, options), run: attestationOf(category, issuer), expect: rej() });
  const rejectedVariant = (difference: string, credential: CredentialSpec, query?: DefaultQueryId) =>
    step({ ...variant(difference, credential, query), expect: rej() });

  const categories = (
    [
      [10, ics.requestsQeaa, queries.qeaa, credentials.qeaa, 'OIA_13, OIA_15b', ['[ETSI TS 119 612]'], 'QEAA', 'qeaa'],
      [12, ics.requestsPubEaa, queries.pubEaa, credentials.pubEaa, 'OIA_14, PuBPNot_06', ['[ETSI TS 119 602]'], 'PuB-EAA', 'pub-eaa'],
      [14, ics.requestsEaa, queries.eaa, credentials.eaa, 'OIA_15', ['[ETSI TS 119 602]'], 'non-qualified EAA', 'eaa'],
    ] as const
  ).map(([number, profile, query, credential, arf, lists, name, category]) =>
    defineTestCase({
      id: id(number, false),
      ...base([profile]),
      objective: `Verify that the Relying Party accepts a ${name} in ${format.name} format signed under the root of trust defined for ${name}s.`,
      references: referencesOf(format, arf, [...lists]),
      steps: [step({ text: scenario.valid({ credential, query }), run: attestationOf(category), expect: acc({ credential, query }) })],
      comments: [comments.flow],
    }),
  );

  return [
    defineTestCase({
      id: id(1, false),
      ...base(),
      objective: `Verify that the Relying Party accepts a PID in ${format.name} format signed under a PID/Issuance anchor of the PID Provider list.`,
      references: referencesOf(format, 'OIA_12, PPNot_05'),
      steps: [step({ ...presentationStep.valid({ credential: pidOf() }), expect: acc({ credential: PID }) })],
      comments: [comments.flow],
    }),
    defineTestCase({
      id: id(2),
      ...base(),
      objective: `Verify that the Relying Party rejects a PID in ${format.name} format signed by a QTSP whose anchor appears only in a Trusted List.`,
      references: referencesOf(format, 'OIA_12, OIA_15', ['[ETSI TS 119 602]', '[ETSI TS 119 612]']),
      steps: [rejectedVariant('it is issued by `QP-A`', pidOf({ issuer: 'QP-A' }))],
      comments: [comments.flow],
    }),
    defineTestCase({
      id: id(3),
      ...base(),
      objective: `Verify that the Relying Party rejects a PID in ${format.name} format signed under an anchor of a list other than the PID Provider list.`,
      references: referencesOf(format, 'OIA_12, OIA_15'),
      steps: [
        rejectedVariant('it is issued by the Wallet Provider `WP-A` from `TL-WP`', pidOf({ issuer: 'WP-A' })),
        rejectedVariant('it is issued by `AC-A` from `TL-AC`', pidOf({ issuer: 'AC-A' })),
        rejectedVariant('it is issued by the PuB-EAA Provider `PB-A` from `TL-PUB`', pidOf({ issuer: 'PB-A' })),
      ],
      comments: [comments.flow],
    }),
    defineTestCase({
      id: id(4),
      ...base(),
      objective: `Verify that the Relying Party rejects a PID in ${format.name} format signed under an anchor published only for the revocation service of a PID Provider.`,
      references: referencesOf(format, 'OIA_12, PPNot_05'),
      steps: [
        rejectedVariant(
          'it is signed by a certificate under the revocation anchor `CA-PP-A-REV` of `PP-A`',
          pidOf({ issuer: 'PP-A', signedUnder: 'revocation' }),
        ),
      ],
      comments: [comments.flow],
    }),
    defineTestCase({
      id: id(5),
      ...base(),
      objective: `Verify that the Relying Party rejects a PID in ${format.name} format from an issuer that is on no trust list.`,
      references: referencesOf(format, 'OIA_12'),
      steps: [rejectedVariant('it is issued by `CA-X`', pidOf({ issuer: 'CA-X' }))],
      comments: [comments.flow],
    }),
    defineTestCase({
      id: id(6),
      ...base(),
      objective: `Verify that the Relying Party rejects a PID in ${format.name} format from a PID Provider whose PID/Issuance service is withdrawn.`,
      references: referencesOf(format, 'OIA_12, OIA_15a'),
      steps: [rejectedVariant('it is issued by `PP-W`, whose PID/Issuance service is withdrawn', pidOf({ issuer: 'PP-W' }))],
      comments: [
        '[ETSI TS 119 602] Annex D gives PID Providers lists no service status. `TL-PID` therefore expresses the withdrawal by listing only the PID/Revocation service of `PP-W`. Its anchor `CA-PP-W` is the one the PID is signed under.',
        comments.flow,
      ],
    }),
    defineTestCase({
      id: id(7),
      ...base(),
      objective: `Verify that the Relying Party stops accepting PIDs in ${format.name} format from a PID Provider once its entry is removed from the PID Provider list.`,
      references: referencesOf(format, 'OIA_15a'),
      steps: [
        step({ ...variant('it is issued by `PP-D`', pidOf({ issuer: 'PP-D' })), expect: acc() }),
        step({
          text: `The Test Trust Infrastructure publishes a new version of \`TL-PID\` without the entry of \`PP-D\`. ${WAIT}`,
          run: { kind: 'trust-list', list: 'TL-PID', remove: ['PP-D'] },
          expect: listRetrieved('TL-PID'),
        }),
        rejectedVariant('it is issued by `PP-D`', pidOf({ issuer: 'PP-D' })),
      ],
      comments: [comments.restoreTrustList, comments.flow],
    }),
    defineTestCase({
      id: id(8, false),
      ...base(),
      objective: `Verify that the Relying Party starts accepting PIDs in ${format.name} format from a PID Provider once its entry is added to the PID Provider list.`,
      references: referencesOf(format, 'OIA_15a'),
      steps: [
        rejectedVariant('it is issued by `PP-C`', pidOf({ issuer: 'PP-C' })),
        step({
          text: `The Test Trust Infrastructure publishes a new version of \`TL-PID\` that adds an entry for \`PP-C\` with a granted PID/Issuance and PID/Revocation service. ${WAIT}`,
          run: { kind: 'trust-list', list: 'TL-PID', add: ['PP-C'] },
          expect: listRetrieved('TL-PID'),
        }),
        step({ ...variant('it is issued by `PP-C`', pidOf({ issuer: 'PP-C' })), expect: acc() }),
      ],
      comments: [comments.restoreTrustList, comments.flow],
    }),
    defineTestCase({
      id: id(9),
      ...base(),
      objective: `Verify that the Relying Party rejects a PID in ${format.name} format signed under an expired trust anchor.`,
      references: referencesOf(format, 'OIA_15a'),
      steps: [rejectedVariant('it is issued by `PP-E`, whose PID/Issuance anchor certificate has expired', pidOf({ issuer: 'PP-E' }))],
      comments: [comments.flow],
    }),
    ...categories,
    defineTestCase({
      id: id(11),
      ...base([ics.requestsQeaa]),
      objective: `Verify that the Relying Party does not accept an attestation in ${format.name} format as QEAA when its issuer has no granted qualified service.`,
      references: referencesOf(format, 'OIA_13, OIA_15b', ['[ETSI TS 119 612]']),
      steps: [
        issuedBy('it is issued by `QP-N`, whose service is not qualified', { credential: credentials.qeaa, query: queries.qeaa }, 'qeaa', 'QP-N'),
        issuedBy('it is issued by `QP-W`, whose qualified service is withdrawn', { credential: credentials.qeaa, query: queries.qeaa }, 'qeaa', 'QP-W'),
      ],
      comments: [comments.flow],
    }),
    defineTestCase({
      id: id(13),
      ...base([ics.requestsPubEaa]),
      objective: `Verify that the Relying Party rejects a PuB-EAA in ${format.name} format signed under a PID Provider anchor.`,
      references: referencesOf(format, 'OIA_14, OIA_15'),
      steps: [issuedBy('it is issued by `PP-A`', { credential: credentials.pubEaa, query: queries.pubEaa }, 'pub-eaa', 'PP-A')],
      comments: [comments.flow],
    }),
    defineTestCase({
      id: id(15),
      ...base([ics.requestsEaa]),
      objective: `Verify that the Relying Party rejects a non-qualified EAA in ${format.name} format signed under an anchor that its rulebook does not define.`,
      references: referencesOf(format, 'OIA_15'),
      steps: [issuedBy('it is issued by `PP-A`', { credential: credentials.eaa, query: queries.eaa }, 'eaa', 'PP-A')],
      comments: [comments.flow],
    }),
    defineTestCase({
      id: id(16),
      ...base([ics.usesTrustedAuthorities]),
      relevancy: relevancy.genericRequired,
      objective: `Verify that the Relying Party enforces the \`trusted_authorities\` of its own request and rejects a PID in ${format.name} format from another trusted PID Provider.`,
      references: ['[OpenID4VP] section 6.1.1.1, 14.9', '[HAIP] section 5', ...trustReferencesOf(format), '[CIR 2024/2982 amended] Annex II'],
      preconditions: [...preconditions.base, preconditions.control(positiveControlOf(format)), preconditions.trustedAuthoritiesOfPpA],
      steps: [rejectedVariant('it is issued by `PP-B`', pidOf({ issuer: 'PP-B' }), pidQueryOf(format.credentialFormat, { trustedAuthorities: true }))],
      comments: ['[OpenID4VP] section 14.9 states that the Verifier must not rely on the Wallet to enforce the constraints of its request.', comments.flow],
    }),
  ];
};

export const definitions = [...trustMechanisms(sdJwtVc), ...trustMechanisms(mdoc)];
