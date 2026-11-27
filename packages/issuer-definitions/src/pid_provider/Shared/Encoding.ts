// PP_WS_SH_Encoding (issuer catalogue section 5.1.5): malformed and oversized requests, URLs in JOSE headers, status
// references to untrusted or private addresses, and a decompression bomb as status list. The faults of `_003_UF` and
// `_004_UF` are those of the points `wia`, `ka` and `proof` (PR 52); `NOFETCH` reads the Test Status Provider's log.
import { defineIssuerTestCase, type FormatVariant, type GrantVariant, relevancy } from '@eudi-pcaf/core';
import { iss, issuance, rej, technologyOf } from '../../wording';
import { both, FORMAT, faultStep, GRANT, MAIN, noFetch, profileOf, ufPreconditions } from '../session';

const encoding001 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SH_Encoding_001_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that the PID Provider rejects malformed JSON, a wrong `Content-Type` and malformed JWTs at its token and credential endpoints without a server error.',
    references: ['[RFC 8725]', '[OpenID4VCI] section 8.3.1'],
    profile: profileOf(format, grant),
    relevancy: relevancy.genericRequired,
    technology: technologyOf(format),
    preconditions: ufPreconditions(),
    steps: (['encoding.truncated-json', 'encoding.text-plain', 'encoding.token-text-plain', 'encoding.two-part-jwt', 'encoding.dpop-two-part-jwt'] as const).map((fault) =>
      faultStep(format, grant, fault, rej()),
    ),
  });

const encoding002 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SH_Encoding_002_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that the PID Provider rejects an oversized request, records how it handles deeply nested JSON, and stays available.',
    references: ['[OWASP API Security Top 10] API4:2023', '[OpenID4VCI] section 8.2', '[RFC8259] section 9'],
    profile: profileOf(format, grant),
    relevancy: relevancy.genericRequired,
    technology: technologyOf(format),
    preconditions: ufPreconditions(),
    steps: [
      faultStep(format, grant, 'encoding.oversized', {
        ...rej(),
        errorObjectOptional: true,
        text: 'The Provider issues no credential and answers with HTTP 4xx (an OAuth error object is not required: a server may refuse an oversized body before OAuth processing, for example with HTTP 413); never HTTP 5xx.',
      }),
      faultStep(format, grant, 'encoding.deep-nesting', {
        codes: ['INFO'],
        text: 'The outcome is recorded; HTTP 5xx fails. The nested member is unknown, which OpenID4VCI 1.0 section 8.2 says "The Credential Issuer MUST ignore", and RFC 8259 section 9 only allows a parser to limit the nesting depth ("may set limits"), so both rejecting and issuing conform.',
      }),
      { text: '`CW-1` runs `SCN-I` for `SUBJ-1` without mutation.', run: issuance(format, grant), expect: iss(format) },
    ],
    comments: [
      'Step 3 shows that the Provider is still available after the two requests.',
      'Spec review 2026-11-20 (issuer catalogue section 8.3): a 413 without an error object is a valid rejection of step 1, and step 2 is informational.',
    ],
  });

const encoding003 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SH_Encoding_003_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that the PID Provider does not dereference a `jku`, `x5u` or `kid` URL in the header of a proof, WIA or KA.',
    references: ['[RFC 8725] section 3.10'],
    profile: profileOf(format, grant),
    relevancy: relevancy.genericRequired,
    technology: technologyOf(format),
    preconditions: ufPreconditions(),
    steps: (['wia.jku-header', 'wia.x5u-header', 'ka.jku-header', 'ka.x5u-header', 'proof.jku-header', 'proof.kid-url'] as const).map((fault) =>
      faultStep(format, grant, fault, both(noFetch, { codes: ['INFO'], text: 'Whether the Provider rejects the request or issues the PID (ignoring the header) is recorded; both conform.' })),
    ),
    comments: [
      'RFC 8725 section 3.10 warns against "blindly following a "jku" (JWK set URL) or "x5u" (X.509 URL) header" and says applications "SHOULD protect against such attacks"; it does not require rejecting a JWS that carries one. The verdict is therefore NOFETCH alone (spec review 2026-11-20, issuer catalogue section 8.3).',
    ],
  });

/** `PP_WS_SH_Encoding_004_UF` steps 5 and 6: a private address in the pre-TS3-1.5 `status` claim, recorded. */
const topLevelInfo = {
  codes: ['INFO' as const],
  text: 'Whether the Provider rejects the request (it read the top-level `status` and could not, or would not, obtain the list) or issues the PID (it ignores the claim) is recorded; HTTP 5xx fails.',
};

const encoding004 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SH_Encoding_004_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that the PID Provider fetches no status `uri` of a WIA or KA that fails signature validation, and no validly signed status `uri` that points to a private address.',
    references: ['[Token Status List] section 6.2', '[Token Status List] section 11.4', '[OWASP] Server-Side Request Forgery'],
    profile: profileOf(format, grant),
    relevancy: relevancy.genericRequired,
    technology: technologyOf(format),
    preconditions: ufPreconditions(),
    steps: [
      faultStep(format, grant, 'wia.ca-x-status-uri', both(rej(), noFetch)),
      faultStep(format, grant, 'ka.ca-x-status-uri', both(rej(), noFetch)),
      faultStep(format, grant, 'wia.status-uri-private', rej()),
      faultStep(format, grant, 'ka.status-uri-private', rej()),
      faultStep(format, grant, 'wia.status-uri-private-top-level', topLevelInfo),
      faultStep(format, grant, 'ka.status-uri-private-top-level', topLevelInfo),
    ],
    comments: [
      'A request to `169.254.169.254` does not reach the Test Status Provider, so the harness cannot log it: steps 3 and 4 expect REJ only. Whether the Provider tried the address is visible in its own logs (for EUDIPLO, `OUTBOUND_URL_ALLOW_PRIVATE_NETWORK` decides).',
      'Steps 3 and 4 put the private address where TS3 1.5 carries the status reference (`client_status`, `key_storage_status`), an EUDI/TS3 requirement. A Provider that reads only the earlier top-level `status` (TS3 1.4.1, OpenID4VCI 1.0 Appendices D.1 and E) never reads that address, so its result there says nothing about server-side request forgery. Steps 5 and 6 (spec review 2026-11-20) add the same address in a top-level `status` next to the valid TS3 reference and record the outcome: such a Provider reads it, and in strict mode refuses the attestation whose status it cannot obtain; one that reads only the TS3 claims ignores it.',
    ],
  });

const encoding005 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SH_Encoding_005_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that the PID Provider refuses a WIA or KA status list that is a decompression bomb without exhausting its resources.',
    references: ['[Token Status List] section 11.1'],
    profile: profileOf(format, grant),
    relevancy: relevancy.genericRequired,
    technology: technologyOf(format),
    preconditions: ufPreconditions(),
    steps: [
      {
        text: 'The Test Status Provider serves `SL-WP-A` as a Status List Token whose `lst` inflates to 1 GiB (fault `status-list.decompression-bomb`).',
        run: { kind: 'wallet-event', event: 'status-list', walletUnit: 'CW-1', statusList: { id: 'SL-WP-A', faults: ['status-list.decompression-bomb'] } },
        expect: { codes: ['INFO'], text: 'The Test Status Provider serves the new version of `SL-WP-A`.' },
      },
      { text: '`CW-1` runs `SCN-I` for `SUBJ-1` without mutation; the Provider reads the status of its WIA and KA in `SL-WP-A`.', run: issuance(format, grant), expect: rej() },
    ],
    comments: ['The Provider must stay available: a later test case of the run that passes shows it.'],
  });

export const definitions = [encoding001, encoding002, encoding003, encoding004, encoding005].map((d) => d(FORMAT, GRANT));
