// RP_WS_SM_Revocation: the status reference in the credential.
import {
  acc,
  all,
  comments,
  credentials,
  defineTestCase,
  type FaultId,
  type FormatWording,
  fetched,
  fetchedIdentifierList,
  formats,
  ics,
  nostat,
  PID,
  pid,
  policyApplicationSpecificStatus,
  positiveControlOf,
  preconditions,
  presentationStep,
  QUERY_PID,
  rej,
  relevancy,
  scenario,
  step,
  technology,
  testCaseId,
} from '@rp-conformance/core';

const sdJwtVc = formats.sdJwtVc;
const mdoc = formats.mdoc;

const SD_JWT_VC_REFERENCES = [
  '[Token Status List] section 6.2, 7.1, 8.3',
  '[SD-JWT VC] section 2.4',
  '[HAIP] section 6.1',
  '[ARF] Annex 2, VCR_11a, VCR_13',
  '[CIR 2024/2979 amended] Annex II',
];
export const MDOC_REVOCATION_REFERENCES = [
  '[Token Status List] section 6.3, 7.1, 8.3',
  '[ISO/IEC 18013-5 ed2]',
  '[HAIP] section 5.3.1',
  '[ARF] Annex 2, VCR_11, VCR_12, VCR_13',
  '[CIR 2024/2979 amended] Annex II',
];
const referencesOf = (format: FormatWording) => (format === sdJwtVc ? SD_JWT_VC_REFERENCES : MDOC_REVOCATION_REFERENCES);

const base = (format: FormatWording) => ({
  profile: [format.profile, ics.checksPidRevocation],
  technology: [format.technology],
  preconditions: [...preconditions.base, preconditions.control(positiveControlOf(format)), preconditions.freshStatusList],
  control: positiveControlOf(format),
});

const MALFORMED_SD_JWT_VC: FaultId[] = [
  'credential.status-no-idx',
  'credential.status-no-uri',
  'credential.status-idx-negative',
  'credential.status-idx-string',
  'credential.status-uri-invalid',
];
const MALFORMED_MDOC = [
  'the `status_list` map in the `status` element of its MSO has no `idx` entry',
  'the `status_list` map in the `status` element of its MSO has no `uri` entry',
  'the `idx` entry of the `status_list` map in its MSO is -1',
  'the `idx` entry of the `status_list` map in its MSO is the text string `7` instead of an unsigned integer',
  'the `uri` entry of the `status_list` map in its MSO is the text string `not a uri`',
];

/** Executable for SD-JWT VC; text only for mdoc until Phase 2. */
const credentialFault = (format: FormatWording, fault: FaultId, mdocDifference: string) =>
  format === sdJwtVc ? presentationStep.credentialFault(fault) : { text: scenario.credentialVariant(mdocDifference) };
const statusValue = (format: FormatWording, value: string, status: number) =>
  format === sdJwtVc ? presentationStep.statusValue(value, status) : { text: scenario.statusValue(value) };

const revocation = (format: FormatWording) => {
  const references = referencesOf(format);
  const withoutAnchor = references.slice(0, -1);
  return [
    defineTestCase({
      id: testCaseId('WS', 'SM', 'Revocation', 1, format.letter),
      ...base(format),
      relevancy: relevancy.specificRequired,
      objective: `Verify that the Relying Party accepts a PID in ${format.name} format whose revocation status is VALID.`,
      references,
      steps: [step({ ...statusValue(format, '0x00 (VALID)', 0), expect: all(acc({ credential: PID }), fetched()) })],
      comments: [comments.flow],
    }),
    defineTestCase({
      id: testCaseId('WS', 'SM', 'Revocation', 2, format.letter, true),
      ...base(format),
      relevancy: relevancy.specificRequired,
      objective: `Verify that the Relying Party rejects a revoked PID in ${format.name} format.`,
      references,
      steps: [step({ ...statusValue(format, '0x01 (INVALID)', 1), expect: rej() })],
      comments: [comments.oidf('oid4vp-1final-verifier-present-revoked-credential'), comments.flow],
    }),
    defineTestCase({
      id: testCaseId('WS', 'SM', 'Revocation', 3, format.letter, true),
      ...base(format),
      relevancy: relevancy.specificRequired,
      objective: `Verify that the Relying Party rejects a suspended PID in ${format.name} format.`,
      references,
      steps: [step({ ...statusValue(format, '0x02 (SUSPENDED)', 2), expect: rej() })],
      comments: [comments.flow],
    }),
    defineTestCase({
      id: testCaseId('WS', 'SM', 'Revocation', 4, format.letter, true),
      ...base(format),
      relevancy: relevancy.genericUndefined,
      objective: `Verify that the Relying Party does not treat an application-specific status value as VALID for a PID in ${format.name} format, unless it declared a meaning for that value.`,
      references,
      steps: [step({ ...statusValue(format, '0x03 (application-specific)', 3), expect: policyApplicationSpecificStatus('0x03') })],
      comments: [comments.flow],
    }),
    defineTestCase({
      id: testCaseId('WS', 'SM', 'Revocation', 5, format.letter, true),
      ...base(format),
      relevancy: relevancy.genericRequired,
      objective: `Verify that the Relying Party rejects a PID in ${format.name} format whose status reference is malformed.`,
      references,
      steps: MALFORMED_SD_JWT_VC.map((fault, i) => step({ ...credentialFault(format, fault, MALFORMED_MDOC[i]), expect: nostat() })),
      comments: [comments.nostat, comments.flow],
    }),
    defineTestCase({
      id: testCaseId('WS', 'SM', 'Revocation', 6, format.letter, true),
      ...base(format),
      relevancy: relevancy.genericRequired,
      objective: `Verify that the Relying Party rejects a PID in ${format.name} format whose status index lies outside the status list.`,
      references,
      steps: [
        step({
          ...credentialFault(
            format,
            'credential.status-idx-out-of-range',
            'the index in its status reference equals the number of entries in the referenced status list, one past the last valid index',
          ),
          expect: rej(),
        }),
      ],
      comments: [comments.flow],
    }),
    defineTestCase({
      id: testCaseId('WS', 'SM', 'Revocation', 7, format.letter),
      ...base(format),
      relevancy: relevancy.specificRequired,
      objective: `Verify that the Relying Party accepts a PID in ${format.name} format without revocation information whose validity period is shorter than 24 hours.`,
      references: [...withoutAnchor, '[ARF] Annex 2, VCR_01, VCR_01b', '[CIR 2024/2979 amended] Annex II'],
      steps: [
        step({
          ...(format === sdJwtVc ? presentationStep.valid({ credential: pid.shortSdJwtVc() }) : { text: scenario.valid({ credential: credentials.pidShort }) }),
          expect: acc({ credential: credentials.pidShort }),
        }),
      ],
      comments: [comments.oidf('oid4vp-1final-verifier-present-credential-without-status'), comments.flow],
    }),
    defineTestCase({
      id: testCaseId('WS', 'SM', 'Revocation', 8, format.letter, true),
      ...base(format),
      relevancy: relevancy.specificRequired,
      objective: `Verify that the Relying Party rejects a PID in ${format.name} format without revocation information whose validity period is longer than 24 hours.`,
      references: [...withoutAnchor, '[ARF] Annex 2, VCR_01, VCR_01b, VCR_14', '[CIR 2024/2979 amended] Annex II'],
      steps: [
        step({ ...credentialFault(format, 'credential.no-status', 'its MSO carries no `status` element'), expect: nostat() }),
      ],
      comments: [
        'A PID valid for longer than 24 hours must carry revocation information ([ARF] Annex 2, VCR_01 and VCR_01b). Without it no reliable revocation status is available, and the Relying Party SUT rejects PIDs in that case.',
        comments.flow,
      ],
    }),
  ];
};

const identifierList = (number: number, listed: boolean) =>
  defineTestCase({
    id: testCaseId('WS', 'SM', 'Revocation', number, '', listed),
    relevancy: relevancy.specificRequired,
    objective: listed
      ? 'Verify that the Relying Party rejects a PID in mdoc format whose identifier is listed in the referenced identifier list.'
      : 'Verify that the Relying Party accepts a PID in mdoc format whose identifier is not listed in the referenced identifier list.',
    references: MDOC_REVOCATION_REFERENCES,
    profile: [mdoc.profile, ics.checksPidRevocation],
    technology: [mdoc.technology, technology.identifierListCwt],
    preconditions: [
      ...preconditions.base,
      preconditions.control(positiveControlOf(mdoc)),
      preconditions.freshStatusList,
      preconditions.identifierList,
    ],
    control: positiveControlOf(mdoc),
    steps: [
      step({
        text: `Perform a presentation for ${QUERY_PID} in which the Conformance Wallet presents ${PID} in a valid Authorization Response, while the referenced identifier list ${listed ? 'contains' : 'does not contain'} the credential's identifier.`,
        expect: listed ? rej() : all(acc({ credential: PID }), fetchedIdentifierList()),
      }),
    ],
    comments: listed
      ? [comments.oidf('oid4vp-1final-verifier-present-credential-on-identifier-list'), comments.flow]
      : [comments.flow],
  });

export const definitions = [...revocation(sdJwtVc), ...revocation(mdoc), identifierList(9, true), identifierList(10, false)];
