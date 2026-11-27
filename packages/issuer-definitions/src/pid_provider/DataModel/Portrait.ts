// PP_WS_DM_Portrait: the PID after the User opted out of the portrait (issuer catalogue section 5.1.4, PID_03). Runs
// only where the Provider offers the opt-out (ICS-17); otherwise the step is NOT APPLICABLE.
import { defineIssuerTestCase, type FormatVariant, type GrantVariant, relevancy } from '@eudi-pcaf/core';
import { conf, expand, OUTPUT_COMMENTS } from '../../output';
import { FORMAT_NAMES, GRANT_NAMES, issuance, pidProfile, preconditions, technologyOf } from '../../wording';

const portrait001 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_DM_Portrait_001',
    variants: [format, grant],
    objective: `Verify that, when the User opts out of the portrait, the PID in ${FORMAT_NAMES[format]} format carries the portrait as ${format === 'SD' ? 'an empty string' : 'an empty `bstr`'}.`,
    references: ['[ARF] Annex 2, PID_03'],
    profile: pidProfile(format, grant),
    relevancy: relevancy.specificOptional,
    technology: technologyOf(format),
    preconditions: [...preconditions.base, 'The Provider offers the portrait opt-out, and the adapter can make `SUBJ-1` opt out (ICS-17).'],
    steps: [
      {
        text: `The adapter creates a credential offer for \`SUBJ-1\`, who opted out of the portrait, and the PID configuration in ${FORMAT_NAMES[format]} format; \`CW-1\` runs \`SCN-I\` in the ${GRANT_NAMES[grant]} without mutation.`,
        run: issuance(format, grant, { portraitOptOut: true }),
        expect: conf(['pid-portrait'], format === 'SD' ? '`picture` is present as an empty string' : '`portrait` is present as an empty byte string', format),
      },
    ],
    comments: [
      'The portrait is `portrait` (`bstr`) in mdoc and `picture` in SD-JWT VC (PID Rulebook chapters 4 and 5).',
      'NOT APPLICABLE when the ICS declares no portrait opt-out (`ICS-17.portrait_opt_out`).',
      ...OUTPUT_COMMENTS,
    ],
  });

export const definitions = expand(['SD', 'MD'], portrait001);
