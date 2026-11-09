// RP_WS_IA_MainInteraction: the positive controls of the unhappy-flow test cases, one per credential format.
import {
  acc,
  comments,
  defineTestCase,
  type FormatWording,
  formats,
  PID,
  pid,
  preconditions,
  presentationStep,
  relevancy,
  scenario,
  step,
  testCaseId,
} from '@rp-conformance/core';

const references = (format: FormatWording) => [
  `[ARF] Annex 2, ${format === formats.sdJwtVc ? 'OIA_03c, OIA_08a, OIA_12' : 'OIA_03b, OIA_08, OIA_12'}`,
  `[HAIP] section 5, ${format === formats.sdJwtVc ? '6.1' : '5.3.1'}`,
  '[OpenID4VP] section 8.6',
  '[CIR 2024/2982 amended] Annex II',
];

const mainInteraction = (format: FormatWording) =>
  defineTestCase({
    id: testCaseId('WS', 'IA', 'MainInteraction', 1, format.letter),
    objective: `Verify that the Relying Party accepts a valid presentation of a PID in ${format.name} format and releases exactly the requested attributes.`,
    references: references(format),
    profile: [format.profile],
    relevancy: relevancy.specificRequired,
    technology: [format.technology],
    preconditions: preconditions.base,
    steps: [
      format === formats.sdJwtVc
        ? step({ ...presentationStep.valid({ query: 'default_query_pid', credential: pid.sdJwtVc() }), expect: acc({ credential: PID }) })
        : step({ text: scenario.valid(), expect: acc({ credential: PID }) }),
    ],
    comments: [comments.positiveControl(format), comments.flow],
  });

export const definitions = [mainInteraction(formats.sdJwtVc), mainInteraction(formats.mdoc)];
