import { acc, comments, defineTestCase, formats, PID, pid, preconditions, presentationStep, relevancy, step } from '@rp-conformance/core';

const format = formats.sdJwtVc;

export default defineTestCase({
  id: 'RP_WS_IA_MainInteraction_001a',
  objective: `Verify that the Relying Party accepts a valid presentation of a PID in ${format.name} format and releases exactly the requested attributes.`,
  references: ['[ARF] Annex 2, OIA_03c, OIA_08a, OIA_12', '[HAIP] section 5, 6.1', '[OpenID4VP] section 8.6', '[CIR 2024/2982 amended] Annex II'],
  profile: [format.profile],
  relevancy: relevancy.specificRequired,
  technology: [format.technology],
  preconditions: preconditions.base,
  steps: [
    step({
      ...presentationStep.valid({ query: 'default_query_pid', credential: pid.sdJwtVc() }),
      expect: acc({ credential: PID }),
    }),
  ],
  comments: [comments.positiveControl(format), comments.flow],
});
