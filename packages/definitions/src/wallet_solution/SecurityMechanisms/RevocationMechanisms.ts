// RP_WS_SM_Revocation_011: a Relying Party that checks the revocation status of mdocs supports both mechanisms, the
// Token Status List and the identifier list of ISO/IEC 18013-5 second edition.
import {
  acc,
  comments,
  defineTestCase,
  formats,
  ics,
  PID,
  positiveControlOf,
  preconditions,
  presentationStep,
  rej,
  relevancy,
  step,
  testCaseId,
} from '@eudi-pcaf/core';

const mdoc = formats.mdoc;

export const definitions = [
  defineTestCase({
    id: testCaseId('WS', 'SM', 'Revocation', 11),
    objective:
      'Verify that the Relying Party, which checks the revocation status of mdocs, supports both revocation mechanisms: it rejects an mdoc revoked through a Status List Token and one revoked through an identifier list, and accepts one that the identifier list does not name.',
    references: ['[ARF] Annex 2, VCR_11, VCR_12', '[ISO/IEC 18013-5 ed2]', '[Token Status List] section 7.1, 8.3', '[CIR 2024/2979 amended] Annex II'],
    profile: [mdoc.profile, ics.checksPidRevocation],
    relevancy: relevancy.specificRequired,
    technology: [mdoc.technology, mdoc.statusListTechnology, 'Identifier list in CWT format.'],
    preconditions: [...preconditions.base, preconditions.control(positiveControlOf(mdoc)), preconditions.freshStatusList],
    control: positiveControlOf(mdoc),
    steps: [
      step({ ...presentationStep.statusValue('0x01 (INVALID)', 1, 'mso_mdoc'), expect: rej() }),
      step({ ...presentationStep.identifierList(true), expect: rej() }),
      step({ ...presentationStep.identifierList(false), expect: acc({ credential: PID }) }),
    ],
    comments: [
      'The steps are those of `RP_WS_SM_Revocation_002b_UF`, `_009_UF` and `_010`: in the first step the MSO references a Status List Token in CWT format, in the other two only an identifier list. The third step shows that a rejection in the second comes from the identifier list, not from a Relying Party that refuses every identifier list.',
      comments.flow,
    ],
  }),
];
