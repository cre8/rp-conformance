// PP_WS_IA_Notification (`P-NOT`, issuer catalogue section 5.1.2): the notification endpoint, with the
// `notification_id` of a credential response and the access token of its session.
import { defineIssuerTestCase, type FormatVariant, type GrantVariant, type IssuerStepDefinition, relevancy } from '@eudi-pcaf/core';
import { iss, issuance, preconditions, technologyOf } from '../../wording';
import { conf, FORMAT, GRANT, MAIN, profileOf, rejAny, ufPreconditions } from '../session';

type NotificationEvent = 'credential_accepted' | 'credential_failure' | 'credential_deleted';
const VCI = '[OpenID4VCI] section 11';

const issue = (format: FormatVariant, grant: GrantVariant): IssuerStepDefinition => ({
  text: '`CW-1` runs `SCN-I` for `SUBJ-1` without mutation; the credential response carries a `notification_id`.',
  run: issuance(format, grant),
  expect: iss(format),
});

const notify = (ofStep: number, event: NotificationEvent): IssuerStepDefinition => ({
  text: `\`CW-1\` sends a notification request with the \`notification_id\` of step ${ofStep}, \`event\` \`${event}\`, the access token of step ${ofStep} and a DPoP proof.`,
  run: { kind: 'notification', ofStep, event, faults: [] },
  expect: conf(['notification-2xx'], 'The notification endpoint answers with HTTP 2xx (OpenID4VCI 1.0 section 11.2: "MUST respond with an HTTP status code in the 2xx range"); whether it is the RECOMMENDED 204 is recorded.'),
});

const notification001 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_Notification_001',
    variants: [format, grant],
    objective: 'Verify that the PID Provider accepts the notification events `credential_accepted`, `credential_failure` and `credential_deleted` with HTTP 2xx.',
    references: [`${VCI}.1`, `${VCI}.2`],
    profile: profileOf(format, grant, 'P-NOT'),
    relevancy: relevancy.genericOptional,
    technology: technologyOf(format),
    preconditions: preconditions.base,
    steps: [issue(format, grant), notify(1, 'credential_accepted'), issue(format, grant), notify(3, 'credential_failure'), issue(format, grant), notify(5, 'credential_deleted')],
    comments: [
      'Each event is sent for a credential of its own, since a `notification_id` belongs to one credential response.',
      'OpenID4VCI 1.0 section 11.2 requires a 2xx and only RECOMMENDS 204, so another 2xx (EUDIPLO answers 201) passes and is recorded in the check detail (spec review 2026-11-20, issuer catalogue section 8.3).',
    ],
  });

const notification002 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_Notification_002_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that the PID Provider rejects an unknown `notification_id`, and record how it answers an unknown event.',
    references: [`${VCI}.3`],
    profile: profileOf(format, grant, 'P-NOT'),
    relevancy: relevancy.genericOptional,
    technology: technologyOf(format),
    preconditions: ufPreconditions(),
    steps: [
      issue(format, grant),
      {
        text: '`CW-1` sends the notification request of the positive case for step 1, except that its `notification_id` is a random value the credential response did not issue (fault `notification.id-unknown`).',
        run: { kind: 'notification', ofStep: 1, event: 'credential_accepted', faults: ['notification.id-unknown'] },
        expect: rejAny('invalid_notification_id', 'invalid_notification_request'),
      },
      {
        text: '`CW-1` sends the notification request of the positive case for step 1, except that its `event` is `foo` (fault `notification.event-unknown`).',
        run: { kind: 'notification', ofStep: 1, event: 'credential_accepted', faults: ['notification.event-unknown'] },
        expect: {
          codes: ['INFO'],
          text: 'The answer is recorded. OpenID4VCI 1.0 section 11.3 prescribes HTTP 400 with an error object only "When the `notification_id` value is invalid"; for an unknown `event` it names `invalid_notification_request` as a code that SHOULD be used, without requiring an error response, so no verdict is given on it.',
        },
      },
    ],
    comments: [
      'Step 3 is informational (spec review 2026-11-20, issuer catalogue section 8.3): the MUST of section 11.3 is scoped to an invalid `notification_id`, which step 2 tests.',
    ],
  });

const notification003 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_Notification_003',
    variants: [format, grant],
    objective: 'Verify that a `credential_deleted` notification, or no notification at all, does not revoke the credential or otherwise act against the User.',
    references: ['[ARF] Annex 2, PAD_03', `${VCI}.1`],
    profile: profileOf(format, grant, 'P-NOT'),
    relevancy: relevancy.specificOptional,
    technology: technologyOf(format),
    preconditions: preconditions.base,
    steps: [
      issue(format, grant),
      {
        text: '`CW-1` sends a notification request with the `notification_id` of step 1 and `event` `credential_deleted`.',
        run: { kind: 'notification', ofStep: 1, event: 'credential_deleted', faults: [] },
        expect: { codes: ['UNCHANGED'], text: 'The credential of step 1 stays valid in the status list the Provider publishes after the notification.' },
      },
      {
        text: '`CW-1` runs `SCN-I` for `SUBJ-1` without mutation and sends no notification.',
        run: issuance(format, grant),
        expect: { codes: ['ISS', 'UNCHANGED'], text: 'The Provider issues the credential, and it stays valid in the status list the Provider publishes.' },
      },
    ],
    comments: ['`UNCHANGED` is observed once, right after the step: the Provider re-signs its status list on every change (ICS-06.T_rev), so a revocation would show.'],
  });

export const definitions = [notification001, notification002, notification003].map((d) => d(FORMAT, GRANT));
