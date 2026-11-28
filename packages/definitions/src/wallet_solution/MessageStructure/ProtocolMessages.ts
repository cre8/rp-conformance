// RP_WS_MS_ProtocolMessages: the Authorization Request the Relying Party sends, by reference via redirects or through
// the W3C Digital Credentials API. `RP_WS_MS_ProtocolMessages_006` (ISO/IEC 18013-7 Annex C) is not written: the
// harness has no Annex C flow.
import { relevancy } from '@eudi-pcaf/core';
import { requestTestCase } from '../requests';

const protocolMessages = (testCase: Omit<Parameters<typeof requestTestCase>[0], 'layer' | 'area'>) =>
  requestTestCase({ layer: 'MS', area: 'ProtocolMessages', ...testCase });

export const definitions = [
  protocolMessages({
    number: 1,
    flow: 'redirect',
    objective: 'Verify that the Relying Party passes its Authorization Request by reference: the invocation URI carries only the Client Identifier and the `request_uri`.',
    references: ['[HAIP] section 5.1', '[RFC9101] section 5.2', '[OpenID4VP] section 5'],
    checks: ['request-by-reference'],
    rule: 'The invocation URI carries `client_id` and `request_uri`, optionally `request_uri_method`, and no other request parameter.',
  }),
  protocolMessages({
    number: 2,
    flow: 'redirect',
    objective: 'Verify that the request object of the Relying Party carries the parameters of a request for response mode `direct_post.jwt`.',
    references: ['[HAIP] section 5, 5.1', '[OpenID4VP] section 5.2, 5.8, 8.2, 8.3.1'],
    checks: ['request-object'],
    rule: 'The request object carries `response_type` `vp_token`, `response_mode` `direct_post.jwt`, an https `response_uri`, no `redirect_uri`, the `client_id` of the invocation URI, a `nonce`, a `dcql_query` and `aud` `https://self-issued.me/v2`.',
  }),
  protocolMessages({
    number: 3,
    count: 20,
    objective: 'Verify that the Relying Party uses a fresh `nonce` of sufficient entropy in every request.',
    references: ['[OpenID4VP] section 5.2, 14.1'],
    checks: ['nonce'],
    rule: 'Every request carries a `nonce` of at least 22 characters from the base64url alphabet (at least 128 bits), and no two requests carry the same `nonce`.',
  }),
  protocolMessages({
    number: 4,
    flow: 'redirect',
    count: 20,
    relevancy: relevancy.genericOptional,
    objective: 'Verify that a `state` the Relying Party uses is fresh and unguessable.',
    references: ['[OpenID4VP] section 5.2, 14.3.2'],
    checks: ['state'],
    rule: 'If the requests carry a `state`, each one is at least 22 characters from the base64url alphabet (at least 128 bits), and no two requests carry the same `state`.',
  }),
  protocolMessages({
    number: 5,
    flow: 'dc-api',
    objective: 'Verify that the Relying Party sends a signed request with response mode `dc_api.jwt` through the W3C Digital Credentials API.',
    references: ['[OpenID4VP] section A.2, A.3.2', '[HAIP] section 5.2', '[ARF] Annex 2, OIA_08, OIA_08a'],
    checks: ['dc-api-request'],
    rule: 'The request uses the protocol `openid4vp-v1-signed` or `openid4vp-v1-multisigned`, and carries `response_mode` `dc_api.jwt` and `expected_origins`. A `response_uri` is recorded in the check detail, not failed: OpenID4VP 1.0 Appendix A.2 allows additional parameters, which the Wallet MUST ignore (spec review 2026-11-20, catalogue section 8.3).',
  }),
];
