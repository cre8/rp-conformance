// RP_WS_SM_RpIntegrity: the Relying Party authenticates its requests with its access certificate and carries its
// registration certificate. Not written: `_008` (several services; no ICS item and no second service in
// `default_configuration_rp_1`), `_009` (intermediaries), `_010` and `_011` (ISO/IEC 18013-5 proximity, which the harness
// does not cover).
import { relevancy } from '@eudi-pcaf/core';
import { requestTestCase } from '../requests';

const rpIntegrity = (testCase: Omit<Parameters<typeof requestTestCase>[0], 'layer' | 'area'>) => requestTestCase({ layer: 'SM', area: 'RpIntegrity', ...testCase });

export const definitions = [
  rpIntegrity({
    number: 1,
    objective: 'Verify that the request object of the Relying Party is a JWS of type `oauth-authz-req+jwt` with an agreed algorithm that verifies with the leaf certificate it carries.',
    references: ['[HAIP] section 5, 7', '[RFC9101] section 10.8', '[ARF] Annex 2, OIA_03'],
    checks: ['request-signature'],
    rule: 'The request object has `typ` `oauth-authz-req+jwt` and `alg` `ES256`, and its signature verifies with the first certificate in `x5c`.',
  }),
  rpIntegrity({
    number: 2,
    objective: 'Verify that the Client Identifier of the Relying Party is the `x509_hash` of its access certificate.',
    references: ['[HAIP] section 5', '[OpenID4VP] section 5.9.3', '[ARF] Annex 2, RPA_02'],
    checks: ['client-id'],
    rule: '`client_id` is `x509_hash:` followed by the base64url SHA-256 hash of the DER encoding of the first certificate in `x5c`.',
  }),
  rpIntegrity({
    number: 3,
    relevancy: relevancy.specificRequired,
    objective: 'Verify that the certificate chain of the Relying Party\'s request validates to an anchor of the list of Access Certificate Authorities.',
    references: ['[HAIP] section 5', '[ARF] Annex 2, RPA_02, RPA_04, Reg_10b'],
    checks: ['access-certificate-chain'],
    rule: '`x5c` holds the access certificate and any intermediate certificates, no trust anchor and no self-signed certificate, and validates to an anchor in `TL-AC`.',
  }),
  rpIntegrity({
    number: 4,
    relevancy: relevancy.specificRequired,
    objective: 'Verify that the Relying Party signs its request with a valid access certificate that carries its identity.',
    references: ['[ETSI TS 119 411-8] section 6.6.1', '[ARF] Annex 2, RPA_02, Reg_32, Reg_33, Reg_34'],
    checks: ['access-certificate'],
    rule: 'The first certificate in `x5c` is valid at the time of the request and follows the access certificate profile, including its policy, its contact information and an entity identifier in its subject.',
  }),
  rpIntegrity({
    number: 5,
    relevancy: relevancy.specificRequired,
    objective: 'Verify that the request of the Relying Party carries its registration certificate, issued for the entity of its access certificate.',
    references: ['[ETSI TS 119 475]', '[ETSI TS 119 472-2]', '[ARF] Annex 2, RPRC_07a, RPRC_10, RPRC_19, RPRC_20'],
    checks: ['registration-certificate'],
    rule: '`verifier_info` carries exactly one registration certificate, by value, whose signature verifies, which validates to an anchor in `TL-RC`, has not expired and names the entity identifier of the access certificate.',
  }),
  rpIntegrity({
    number: 6,
    relevancy: relevancy.specificRequired,
    objective: 'Verify that the Relying Party never sends an unsigned request.',
    references: ['[HAIP] section 5.1', '[ARF] Annex 2, RPA_01, RPA_03'],
    checks: ['signed-request'],
    rule: 'Via redirects the request object is signed; via the W3C Digital Credentials API the request uses the protocol `openid4vp-v1-signed` or `openid4vp-v1-multisigned`.',
  }),
  rpIntegrity({
    number: 7,
    flow: 'dc-api',
    objective: 'Verify that the signed request of the Relying Party through the W3C Digital Credentials API names only its own Origin in `expected_origins`.',
    references: ['[OpenID4VP] section A.2, A.3.2'],
    checks: ['expected-origins'],
    rule: '`expected_origins` names the Origin of the Relying Party\'s page and no other.',
  }),
];
