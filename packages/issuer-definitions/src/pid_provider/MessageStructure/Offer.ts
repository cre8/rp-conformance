// PP_WS_MS_Offer (issuer catalogue section 5.1.1): the credential offer the adapter obtains from the Provider. The
// Conformance Wallet resolves the offer and fetches the metadata of its issuer, without redeeming it (`Capture`).
import { defineIssuerTestCase, type FormatVariant, type GrantVariant, relevancy } from '@eudi-pcaf/core';
import { FORMAT_NAMES, GRANT_NAMES, iss, issuance, pidProfile, preconditions, technologyOf } from '../../wording';
import { conf } from './conf';

const capture = (format: FormatVariant, grant: GrantVariant, byReference: boolean) =>
  `The adapter creates a credential offer for \`SUBJ-1\` and the PID configuration in ${FORMAT_NAMES[format]} format, ${GRANT_NAMES[grant]}, ${byReference ? 'by reference (`credential_offer_uri`)' : 'by value (`credential_offer`)'}. \`CW-1\` resolves it${byReference ? ', fetching `credential_offer_uri`,' : ''} and fetches the Credential Issuer metadata of its \`credential_issuer\`, without redeeming the offer.`;

const ISSUER_AND_CONFIGURATIONS = {
  'offer-issuer': '`credential_issuer` is an https URL without query or fragment and equals the `credential_issuer` of the metadata served under it',
  'offer-configurations': '`credential_configuration_ids` is a non-empty array of distinct IDs, each a key of `credential_configurations_supported`',
} as const;

const base = (format: FormatVariant, grant: GrantVariant) => ({
  variants: [format, grant],
  profile: pidProfile(format, grant),
  technology: technologyOf(format),
  preconditions: preconditions.base,
});

const offer001 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_MS_Offer_001',
    ...base(format, grant),
    objective: "Verify that the credential offer names the Provider's `credential_issuer` and only `credential_configuration_ids` that exist in the metadata.",
    references: ['[OpenID4VCI] section 4.1.1'],
    relevancy: relevancy.genericRequired,
    steps: [{ text: capture(format, grant, false), run: issuance(format, grant), expect: conf(ISSUER_AND_CONFIGURATIONS) }],
  });

const offer002 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_MS_Offer_002',
    ...base(format, grant),
    objective: 'Verify that an offer by reference is served as `application/json` over https and equals an offer by value.',
    references: ['[OpenID4VCI] section 4.1.3'],
    relevancy: relevancy.genericRequired,
    steps: [
      { text: capture(format, grant, false), run: issuance(format, grant), expect: conf(ISSUER_AND_CONFIGURATIONS) },
      {
        text: capture(format, grant, true),
        run: issuance(format, grant, { offerByReference: true }),
        expect: conf({
          'offer-reference-fetch': '`credential_offer_uri` is an https URL and is answered HTTP 200 with `application/json`',
          'offer-reference-equal': 'the offer equals the offer by value of step 1 in every member except the values of the session: `pre-authorized_code` and `issuer_state`',
        }),
      },
    ],
  });

const offer003 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_MS_Offer_003',
    ...base(format, 'PA'),
    objective: 'Verify that the pre-authorized code of an offer is opaque, and that `tx_code` carries `input_mode`, `length` and `description` when a transaction code is required.',
    references: ['[OpenID4VCI] section 4.1.1'],
    relevancy: relevancy.genericRequired,
    steps: [
      {
        text: `${capture(format, 'PA', false)} The offer is protected by a transaction code unless the ICS declares offers without one only (ICS-03).`,
        run: issuance(format, 'PA'),
        expect: conf({
          'offer-pre-authorized-code':
            '`pre-authorized_code` is a non-empty string that is neither a JWT nor base64url-encoded JSON; where the adapter obtained a transaction code, `tx_code` is present with `input_mode` `numeric` or `text`, a positive integer `length` and a `description` of at most 300 characters',
        }),
      },
    ],
  });

const offer004 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_MS_Offer_004',
    ...base(format, 'AC'),
    objective: 'Verify that the `issuer_state` of an authorization code offer, if present, is bound to the offer and accepted when it is returned unaltered.',
    references: ['[OpenID4VCI] sections 4.1.1 and 5.1.3'],
    relevancy: relevancy.genericOptional,
    steps: [
      { text: capture(format, 'AC', false), run: issuance(format, 'AC'), expect: conf({ 'offer-issuer-state': '`issuer_state`, if present, is a non-empty string' }) },
      {
        text: `The adapter creates a second offer as in step 1. \`CW-1\` runs \`SCN-I\` in the ${GRANT_NAMES.AC} and returns the \`issuer_state\` of that offer unaltered in its pushed authorization request.`,
        run: issuance(format, 'AC'),
        expect: iss(format),
      },
    ],
    comments: ['Step 2 shows that the Provider accepts its own `issuer_state`; that an `issuer_state` of another offer is refused is not part of the objective.'],
  });

export const definitions = [offer001('SD', 'PA'), offer001('SD', 'AC'), offer002('SD', 'PA'), offer002('SD', 'AC'), offer003('SD'), offer004('SD')];
