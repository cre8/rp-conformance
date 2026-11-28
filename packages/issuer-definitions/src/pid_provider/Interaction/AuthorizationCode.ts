// PP_WS_IA_AuthorizationCode: the authorization code flow with PAR and PKCE (issuer catalogue section 5.1.2). One
// definition per format variant; the grant is `AC` by definition. The faults are those of the points `authorization`
// and `token-request` (`GRANT_FAULTS`); reusing a `request_uri` or a code is a `token-reuse` step.
import { defineIssuerTestCase, type FormatVariant, GRANT_FAULTS, type GrantFaultId, type IssuerExpectation, relevancy } from '@eudi-pcaf/core';
import { FORMAT_NAMES, iss, issuance, pidProfile, preconditions, rej, technologyOf } from '../../wording';

const CONTROL = 'PP_WS_IA_MainInteraction_001';
const OFFER = (format: FormatVariant) =>
  `The adapter creates a credential offer for \`SUBJ-1\` and the PID configuration in ${FORMAT_NAMES[format]} format, authorization code grant with \`issuer_state\`.`;
const faultStep = (format: FormatVariant, fault: GrantFaultId, code?: string) => ({
  text: `${OFFER(format)} \`CW-1\` runs \`SCN-I\` as in \`${CONTROL}\`, except that ${GRANT_FAULTS[fault].text} (fault \`${fault}\`).`,
  run: issuance(format, 'AC', { faults: [fault] }),
  expect: rej(code),
});
const validStep = (format: FormatVariant) => ({
  text: `${OFFER(format)} \`CW-1\` runs \`SCN-I\` without mutation: PAR with PKCE \`S256\`, the authorization request through the adapter, token request with \`code_verifier\`, nonce and credential request.`,
  run: issuance(format, 'AC'),
  expect: iss(format),
});
const base = (format: FormatVariant) => ({
  variants: [format, 'AC' as const],
  profile: pidProfile(format, 'AC'),
  technology: technologyOf(format),
  preconditions: [...preconditions.base, 'The adapter completes the authentication of `SUBJ-1` at the Provider (`authenticateSubject`, ICS-03).', preconditions.control(CONTROL)],
  control: CONTROL,
});

/** `CONF` on the authorization response (RFC 6749 section 4.1.2, RFC 9207). */
const conf = (text: string, checks: string[]): IssuerExpectation => ({ codes: ['CONF'], text, checks });

const authorizationCode001 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_AuthorizationCode_001_UF',
    ...base(format),
    objective: 'Verify that the PID Provider rejects an authorization request that was not pushed with PAR.',
    references: ['[HAIP] sections 4 and 4.3', '[RFC 9126] section 5'],
    relevancy: relevancy.specificRequired,
    steps: [faultStep(format, 'authorization.no-par')],
    comments: [
      'The authorization endpoint rejects with a redirect carrying `error`, or, since no pushed request names the client, with an error page (HTTP 4xx, RFC 6749 section 4.1.2.1); either passes, an authorization code or a token does not. OIDF `fapi2-…-ensure-unsigned-authorization-request-without-using-par-fails`.',
    ],
  });

const authorizationCode002 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_AuthorizationCode_002_UF',
    ...base(format),
    objective: 'Verify that the PID Provider rejects a pushed authorization request without PKCE, and one with the PKCE method `plain`.',
    references: ['[HAIP] section 4', '[RFC 7636] section 4.3'],
    relevancy: relevancy.specificRequired,
    steps: [faultStep(format, 'authorization.pkce-missing'), faultStep(format, 'authorization.pkce-plain')],
    comments: ['OIDF `fapi2-…-par-ensure-pkce-required` and `fapi2-…-par-plain-pkce-rejected`. Each step uses a new offer.'],
  });

const authorizationCode003 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_AuthorizationCode_003_UF',
    ...base(format),
    objective: 'Verify that the PID Provider rejects a token request whose `code_verifier` is wrong or missing with `invalid_grant`.',
    references: ['[RFC 7636] section 4.6'],
    relevancy: relevancy.genericRequired,
    steps: [faultStep(format, 'token-request.code-verifier-wrong', 'invalid_grant'), faultStep(format, 'token-request.code-verifier-missing', 'invalid_grant')],
    comments: ['OIDF `fapi2-…-incorrect-pkce-code-verifier-rejected` and `fapi2-…-ensure-pkce-code-verifier-required`. Each step uses a new offer.'],
  });

const authorizationCode004 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_AuthorizationCode_004_UF',
    ...base(format),
    objective: 'Verify that the PID Provider accepts a PAR `request_uri` only once and only before it expires.',
    references: ['[RFC 9126] sections 4 and 7.3'],
    relevancy: relevancy.genericRequired,
    steps: [
      validStep(format),
      {
        text: '`CW-1` sends the authorization request of step 1 again, with the same `client_id` and `request_uri`, through the adapter.',
        run: { kind: 'token-reuse', artifact: 'par-request-uri', ofStep: 1 },
        expect: rej(),
      },
      faultStep(format, 'authorization.request-uri-expired'),
    ],
    comments: [
      'One-time use is a SHOULD in RFC 9126 section 7.3 (OIDF `fapi2-…-par-attempt-reuse-request_uri` reports success as a WARNING); the catalogue requires the rejection.',
      'Step 3 waits the `expires_in` of the PAR response plus one hour (issuer catalogue section 3.5; OIDF `fapi2-…-par-attempt-to-use-expired-request_uri`). It runs only when the run allows that wait (`--max-wait`), and then last; otherwise it is NOT APPLICABLE in the run and the verdict is that of steps 1 and 2. Against EUDIPLO (`expires_in` 60) it waits 61 minutes.',
    ],
  });

const authorizationCode005 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_AuthorizationCode_005_UF',
    ...base(format),
    preconditions: [...base(format).preconditions.slice(0, -1), 'Wallet Unit `CW-2` of `WP-A` (section 3.4).', preconditions.control(CONTROL)],
    objective:
      'Verify that the PID Provider redeems an authorization code only once, only for the client it was issued to, and only with the `redirect_uri` of its authorization request; each other redemption is rejected with `invalid_grant`.',
    references: ['[RFC 6749] sections 4.1.3, 5.2 and 10.5'],
    relevancy: relevancy.genericRequired,
    steps: [
      validStep(format),
      {
        text: '`CW-1` sends the token request of step 1 again: the same `code`, `code_verifier` and `redirect_uri`, with a fresh WIA PoP and DPoP proof.',
        run: { kind: 'token-reuse', artifact: 'authorization-code', ofStep: 1 },
        expect: rej('invalid_grant'),
      },
      {
        text: `${OFFER(format)} \`CW-1\` runs \`SCN-I\` without mutation up to the authorization response, and sends no token request.`,
        run: issuance(format, 'AC', { stopAfterAuthorization: true }),
        expect: conf('The Provider redirects to the `redirect_uri` of `CW-1` with an authorization code.', ['authorization-response-code']),
      },
      {
        text: '`CW-2` sends a token request with the `code`, `code_verifier` and `redirect_uri` of step 3, authenticated with its own WIA, PoP, DPoP proof and `client_id`.',
        run: { kind: 'token-reuse', artifact: 'authorization-code', ofStep: 3, walletUnit: 'CW-2' },
        expect: rej('invalid_grant'),
      },
      faultStep(format, 'token-request.redirect-uri-other', 'invalid_grant'),
    ],
    comments: [
      'OIDF `fapi2-…-attempt-reuse-authorization-code-after-one-second` and `fapi2-…-ensure-authorization-code-is-bound-to-client` (partial: the OIDF plan does not test the `redirect_uri` binding). Revoking the tokens of step 1 after the reuse is not required here.',
      'Steps 2 and 4 send valid messages; only the code was redeemed before (step 2) or issued to another client (step 4). The reference validator fails `authorization-code` and `code-binding` on them.',
    ],
  });

const authorizationCode006 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_AuthorizationCode_006_UF',
    ...base(format),
    objective:
      'Verify that the PID Provider rejects an authorization request for an unknown `credential_configuration_id` in `authorization_details`, and ignores an unknown `scope` value next to a valid request.',
    references: ['[OpenID4VCI] sections 5.1.1 and 5.1.2'],
    relevancy: relevancy.genericRequired,
    steps: [
      faultStep(format, 'authorization.authorization-details-unknown'),
      {
        text: `${OFFER(format)} \`CW-1\` runs \`SCN-I\` as in \`${CONTROL}\`, except that ${GRANT_FAULTS['authorization.scope-unknown'].text} (mutation \`authorization.scope-unknown\`).`,
        run: issuance(format, 'AC', { faults: ['authorization.scope-unknown'] }),
        expect: { ...iss(format), text: 'The unknown `scope` value is ignored (OpenID4VCI 1.0 section 5.1.2: "Credential Issuers MUST ignore unknown scope values in a request"): the PID is issued as requested by the `authorization_details`.' },
      },
    ],
    comments: [
      'The rejection of step 1 may come at PAR, at the authorization endpoint or at the token endpoint; the step passes when the request at which the flow ends is rejected and no credential is issued. Each step uses a new offer.',
      'Step 2 does not expect a rejection: OpenID4VCI 1.0 section 5.1.2 requires a Credential Issuer to ignore unknown scope values, so the request is valid apart from a value the Provider must disregard (decision in the catalogue section 5.1.2, spec review 2026-11-20).',
    ],
  });

const authorizationCode007 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_AuthorizationCode_007',
    ...base(format),
    objective: 'Verify that the PID Provider returns the `state` of the authorization request unaltered, and its issuer identifier as `iss`, in the authorization response.',
    references: ['[RFC 6749] section 4.1.2', '[RFC 9207] section 2', '[HAIP] section 4'],
    relevancy: relevancy.genericRequired,
    steps: [
      {
        text: `${OFFER(format)} \`CW-1\` runs \`SCN-I\` without mutation up to the authorization response, and captures it.`,
        run: issuance(format, 'AC', { stopAfterAuthorization: true }),
        expect: conf(
          'The redirect to the `redirect_uri` of `CW-1` carries `state` equal to the `state` of the pushed authorization request, and `iss` equal to the `issuer` of the Authorization Server metadata.',
          ['authorization-response-state', 'authorization-response-iss'],
        ),
      },
    ],
    comments: ['OIDF `fapi2-…-happy-flow`. A positive check: it is gated on the positive control like the `_UF` test cases of the area, since it needs the same working flow.'],
  });

export const definitions = (['SD'] as const).flatMap((format) => [
  authorizationCode001(format),
  authorizationCode002(format),
  authorizationCode003(format),
  authorizationCode004(format),
  authorizationCode005(format),
  authorizationCode006(format),
  authorizationCode007(format),
]);
