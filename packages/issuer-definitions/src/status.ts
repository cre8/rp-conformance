// Building blocks of the revocation and status list test cases (issue 22): the `observe-status`, `issuer-event` and
// `present` steps, and the wording of the checks `OBS-SL` runs on a published status list (issuer harness design section
// 6.3, catalogue sections 3.6 and 5.2).
import type { FormatVariant, IssuerExpectation, IssuerStepDefinition } from '@eudi-pcaf/core';
import { FORMAT_NAMES, iss, issuance } from './wording';

/** The token format of the status list a credential of the format references. */
export const LIST_FORMAT: Record<FormatVariant, string> = { SD: 'JWT (`application/statuslist+jwt`)', MD: 'CWT (`application/statuslist+cwt`)' };

/** What each check of `OBS-SL` establishes, as the FCAF text names it. */
export const STATUS_CHECK_TEXT: Record<string, string> = {
  'status-list-fetch': '`status-list-fetch` (HTTP 200)',
  'status-list-format': '`status-list-format` (a Status List Token in the format of the credential)',
  'status-list-type': '`status-list-type` (`typ` `statuslist+jwt`, or `application/statuslist+cwt`)',
  'status-list-trust': '`status-list-trust` (the signer chains to the revocation anchor of `PP-T` on `TL-PID`, or to its issuance anchor where the list carries it under both services)',
  'status-list-signature': '`status-list-signature` (`ES256`, verifies with the signer certificate)',
  'status-list-claims': '`status-list-claims` (`sub`, `iat`, `status_list` with `bits` and `lst`)',
  'status-list-subject': "`status-list-subject` (`sub` equals the credential's status `uri`)",
  'status-list-validity': '`status-list-validity` (`exp` not passed)',
  'status-list-decoding': '`status-list-decoding` (`bits` is 1, 2, 4 or 8; `lst` is valid ZLIB data)',
  'status-index': '`status-index` (the credential\'s `idx` lies within the decoded entries)',
  status: '`status` (the credential is valid, `0x00`)',
  'sl-uri': '`sl-uri` (an https URI without user information; an http URI on the loopback host stands for https in a local run)',
  'sl-anonymous': '`sl-anonymous` (HTTP 200 to a GET without `Authorization` header or cookie, no authentication challenge)',
  'sl-media-type': '`sl-media-type` (for each format the ICS declares (ICS-05), `Accept` of that media type is answered with that `Content-Type` and a token in that format)',
  'sl-cache': '`sl-cache` (if `Cache-Control` or `Expires` is present: `max-age` no longer than `ttl` and not beyond `exp`, `Expires` not after `exp`, or `no-cache`/`no-store`; no header at all passes)',
  'sl-uri-privacy': '`sl-uri-privacy` (no status URI carries a query or fragment, the response sets no cookie, and the credentials share their status URIs instead of one URI per credential)',
  'sl-lifetime': '`sl-lifetime` (`iat`, `exp` and `ttl` present; `exp` after `iat` and in the future; `ttl` positive)',
  'sl-entries': '`sl-entries` (at least the minimum number of entries of ICS-16, and at least 10 000)',
  'sl-algorithm': '`sl-algorithm` (an ECCG agreed ECDSA algorithm with a key on an agreed curve)',
  'sl-signer-validity': "`sl-signer-validity` (the signer certificate is valid from the token's `iat` to its `exp`)",
  'sl-continuity': "`sl-continuity` (polls continue past the first version's `exp`; no poll returns an expired token)",
};

/** `CONF` over the published status list: the named checks pass for every credential observed. */
export function published(checks: string[], what: string): IssuerExpectation {
  return {
    codes: ['CONF'],
    checks,
    text: `${what} The named checks pass: ${checks.map((check) => STATUS_CHECK_TEXT[check] ?? `\`${check}\``).join('; ')}.`,
  };
}

/** The issuance step every test case of the area starts with: `SCN-I` without mutation, `ISS`. */
export const issueStep = (format: FormatVariant): IssuerStepDefinition => ({
  text: `The adapter creates a credential offer for \`SUBJ-1\` and the PID configuration in ${FORMAT_NAMES[format]} format, pre-authorized code. \`CW-1\` runs \`SCN-I\` without mutation.`,
  run: issuance(format, 'PA'),
  expect: iss(format),
});

/** One anonymous fetch (`SCN-P`) of the status list the credentials of `ofSteps` reference. */
export const fetchStep = (format: FormatVariant, ofSteps: number[], expect: IssuerExpectation, extra = ''): IssuerStepDefinition => ({
  text: `The harness fetches the status list the credential of step${ofSteps.length > 1 ? 's' : ''} ${ofSteps.length > 2 ? `${ofSteps[0]} to ${ofSteps.at(-1)}` : ofSteps.join(' and ')} references, anonymously (no \`Authorization\` header, no cookie), with \`Accept\` \`${format === 'SD' ? 'application/statuslist+jwt' : 'application/statuslist+cwt'}\`, and once with the \`Accept\` of each format the ICS declares (ICS-05).${extra ? ` ${extra}` : ''}`,
  run: { kind: 'observe-status', ofSteps, t: 'PT0S' },
  expect,
});

/** The adapter revokes what an earlier issuance step received (`setStatus`, ICS-06). */
export const revokeStep = (ofStep: number): IssuerStepDefinition => ({
  text: `The adapter revokes the credential of step ${ofStep} (\`setStatus\` revoked) and reports when the Provider has done so (\`OBS-ADM\`).`,
  run: { kind: 'issuer-event', event: 'set-status', status: 'revoked', ofStep },
  expect: { codes: ['INFO'], text: 'The time the adapter reports is recorded; the window of the next step counts from it.' },
});

/** `OBS-SL` for `T_rev` after the event: `REVOKED(T_rev)`. */
export const revokedStep = (ofStep: number): IssuerStepDefinition => ({
  text: `The harness polls the status list of the credential of step ${ofStep} anonymously every \`min(T_rev / 20, 30 s)\` until \`T_rev\` (ICS-06) after the time the adapter reported, keeping every version with its \`iat\`, \`exp\` and the credential's status.`,
  run: { kind: 'observe-status', ofSteps: [ofStep], t: 'T_rev' },
  expect: {
    codes: ['REVOKED(T_rev)'],
    text: "No later than `T_rev` after the reported revocation, a version of the list shows the credential's entry as `0x01` (INVALID), and every later version polled shows it as `0x01` too.",
  },
});
