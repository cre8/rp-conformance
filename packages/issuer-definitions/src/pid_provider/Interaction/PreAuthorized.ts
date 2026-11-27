// PP_WS_IA_PreAuthorized: the pre-authorized code is single-use, protected by its `tx_code`, limited in time, and bound
// to its offer (issuer catalogue section 5.1.2). One definition per format variant; the grant is `PA` by definition.
// The faults are those of the point `token-request` (`GRANT_FAULTS`), the reuse is a `token-reuse` step.
import { defineIssuerTestCase, type FormatVariant, GRANT_FAULTS, type GrantFaultId, relevancy } from '@eudi-pcaf/core';
import { FORMAT_NAMES, iss, issuance, pidProfile, preconditions, rej, technologyOf } from '../../wording';

const CONTROL = 'PP_WS_IA_MainInteraction_001';
const OFFER = (format: FormatVariant) =>
  `The adapter creates a credential offer for \`SUBJ-1\` and the PID configuration in ${FORMAT_NAMES[format]} format, pre-authorized code with \`tx_code\`.`;
const faultStep = (format: FormatVariant, fault: GrantFaultId, code?: string) => ({
  text: `${OFFER(format)} \`CW-1\` runs \`SCN-I\` as in \`${CONTROL}\`, except that ${GRANT_FAULTS[fault].text} (fault \`${fault}\`).`,
  run: issuance(format, 'PA', { faults: [fault] }),
  expect: rej(code),
});
const base = (format: FormatVariant) => ({
  variants: [format, 'PA' as const],
  profile: pidProfile(format, 'PA'),
  technology: technologyOf(format),
  preconditions: [...preconditions.base, preconditions.control(CONTROL)],
  control: CONTROL,
});

const preAuthorized001 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_PreAuthorized_001_UF',
    ...base(format),
    objective: 'Verify that the PID Provider accepts a pre-authorized code only once: a second token request with the same code is rejected with `invalid_grant`.',
    references: ['[OpenID4VCI] sections 4.1.1, 6.3 and 13.6.1'],
    relevancy: relevancy.genericRequired,
    steps: [
      {
        text: `${OFFER(format)} \`CW-1\` runs \`SCN-I\` without mutation.`,
        run: issuance(format, 'PA'),
        expect: iss(format),
      },
      {
        text: '`CW-1` sends the token request of step 1 again: the same `pre-authorized_code` and `tx_code`, with a fresh WIA PoP and DPoP proof.',
        run: { kind: 'token-reuse', artifact: 'pre-authorized-code', ofStep: 1 },
        expect: rej('invalid_grant'),
      },
    ],
    comments: ['The reuse is not a fault of the request: every message of step 2 is valid, only its code was redeemed in step 1 (the reference validator fails `pre-authorized-code` on it).'],
  });

const preAuthorized002 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_PreAuthorized_002_UF',
    ...base(format),
    objective:
      'Verify that the PID Provider rejects a token request with a wrong `tx_code` with `invalid_grant` and one without the `tx_code` the offer requires with `invalid_request`, and that it limits repeated wrong values: after ten wrong `tx_code` values even the right one is refused.',
    references: ['[OpenID4VCI] sections 6.1, 6.3 and 13.6.1'],
    relevancy: relevancy.genericRequired,
    steps: [
      faultStep(format, 'token-request.tx-code-wrong', 'invalid_grant'),
      faultStep(format, 'token-request.tx-code-missing', 'invalid_request'),
      faultStep(format, 'token-request.tx-code-repeated'),
    ],
    comments: [
      'Each step uses a new offer. OpenID4VCI section 6.3 names the error of each: `invalid_grant` for a wrong `tx_code` (step 1), `invalid_request` when the Authorization Server expects a `tx_code` and the Client provides none (step 2). Step 3 expects `REJ` with any error code for the last, right `tx_code`: OpenID4VCI 1.0 sets no limit on wrong attempts (issuer catalogue section 8.2), the limit rests on its security considerations (section 13.6.1) and ISSU policy.',
      'Applies when the Provider protects pre-authorized codes with a `tx_code` (ICS-03.tx_code); the runner reports the test case NOT APPLICABLE for a Provider that declares offers without one only.',
    ],
  });

const preAuthorized003 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_PreAuthorized_003_UF',
    ...base(format),
    objective: 'Verify that the PID Provider rejects a pre-authorized code after its lifetime with `invalid_grant`.',
    references: ['[OpenID4VCI] sections 4.1.1 and 6.3'],
    relevancy: relevancy.genericRequired,
    steps: [faultStep(format, 'token-request.pre-authorized-code-expired', 'invalid_grant')],
    comments: [
      'The lifetime is the one the Provider declares (ICS-14.pre_authorized_code); the token request is sent one hour after it (issuer catalogue section 3.5).',
      'The step waits that long only when the run allows it (`--max-wait`), and then runs last; otherwise it is NOT APPLICABLE in the run. Against EUDIPLO (ICS-14.pre_authorized_code PT24H) it waits 25 hours, so the reference run does not execute it.',
    ],
  });

const preAuthorized004 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_PreAuthorized_004_UF',
    ...base(format),
    objective:
      "Verify that the pre-authorized code of one offer of the PID Provider gives no access to the credential configuration of another offer: a credential request for this offer's configuration with the access token of the other offer's code is rejected.",
    references: ['[OpenID4VCI] sections 4.1.1 and 8.3.1.2'],
    relevancy: relevancy.genericRequired,
    preconditions: [
      ...preconditions.base,
      'The Provider offers a second credential configuration of another credential type (ICS-02.second), and the adapter can create an offer for it.',
      preconditions.control(CONTROL),
    ],
    steps: [
      {
        ...faultStep(format, 'token-request.pre-authorized-code-other-offer'),
        text: `${OFFER(format)} It also creates a second offer for \`SUBJ-1\` and the configuration \`ICS-02.second\`. \`CW-1\` runs \`SCN-I\` for the first offer as in \`${CONTROL}\`, except that ${GRANT_FAULTS['token-request.pre-authorized-code-other-offer'].text} (fault \`token-request.pre-authorized-code-other-offer\`).`,
      },
    ],
    comments: [
      'The token request itself is valid for the second offer, so the Provider may issue its token; the request at which the flow ends is the credential request for the first offer\'s configuration, which must be rejected (`REJ` with any error code, for example `invalid_credential_request` or `invalid_token`).',
    ],
  });

export const definitions = (['SD'] as const).flatMap((format) => [preAuthorized001(format), preAuthorized002(format), preAuthorized003(format), preAuthorized004(format)]);
