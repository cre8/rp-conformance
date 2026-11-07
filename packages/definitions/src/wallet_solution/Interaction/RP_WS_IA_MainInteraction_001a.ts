import { acc, defineTestCase, ics, pid, presentation, step } from '@rp-conformance/core';

export default defineTestCase({
  id: 'RP_WS_IA_MainInteraction_001a',
  objective:
    'Verify that the Relying Party accepts a valid presentation of a PID in SD-JWT VC format and releases exactly the requested attributes.',
  references: ['[ARF] Annex 2, OIA_03c, OIA_08a, OIA_12', '[HAIP] section 5, 6.1', '[OpenID4VP] section 8.6', '[CIR 2024/2982 amended] Annex II'],
  profile: [ics.requestsSdJwtVc],
  relevancy: 'EUDI_specific | EUDI_required',
  technology: ['Presentation of a credential in IETF SD-JWT VC format.'],
  preconditions: [
    'The Relying Party is set to `default_configuration_rp_1`.',
    'The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.',
  ],
  steps: [
    step({
      text: 'Perform a presentation for `default_query_pid` in which the Conformance Wallet presents `default_credential_pid` in a valid Authorization Response.',
      expectedText:
        'The Relying Party accepts the presentation: its verification result reports success and releases exactly the attributes requested in `default_query_pid`, with the values of `default_credential_pid`.',
      run: presentation({ query: 'default_query_pid', credential: pid.sdJwtVc() }),
      expect: acc(),
    }),
  ],
  comments: [
    'This test case is the positive control for the unhappy-flow test cases of the Relying Party SUT that present a credential in SD-JWT VC format. When it fails, those test cases cannot produce a meaningful verdict in the same environment.',
    'Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).',
  ],
});
