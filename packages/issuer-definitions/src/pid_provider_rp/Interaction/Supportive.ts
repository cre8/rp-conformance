// PP_RP_IA_Supportive_001 to _003 (issuer catalogue section 5.2, `SCN-P`): how the Provider serves its status lists to
// Relying Parties. No format is named: each runs in `SD` until the mdoc PID lands (issue 21), and in `PA`, since the grant
// does not change what is published.
import { defineIssuerTestCase, type FormatVariant, issuerProfiles, relevancy } from '@eudi-pcaf/core';
import { fetchStep, issueStep, published } from '../../status';
import { pidProfile, preconditions, technologyOf } from '../../wording';

const base = (format: FormatVariant) => ({
  profile: [...pidProfile(format, 'PA'), issuerProfiles['P-REV']],
  technology: [...technologyOf(format), 'Token Status List', 'HTTP'],
  preconditions: preconditions.base,
});

const supportive001 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_RP_IA_Supportive_001',
    ...base(format),
    variants: [format, 'PA'],
    objective: 'Verify that the Provider serves its status list without authentication, over https, with `Content-Type` `application/statuslist+jwt` or `application/statuslist+cwt` as `Accept` asks for.',
    references: ['[ARF] Annex 2, VCR_16', '[TokenStatusList] section 8.1'],
    relevancy: relevancy.specificRequired,
    steps: [issueStep(format), fetchStep(format, [1], published(['sl-uri', 'sl-anonymous', 'sl-media-type'], 'The status list is served to anyone, over https, in the format `Accept` names.'))],
    comments: ['OIDF `happy-flow` covers this objective partly: JWT only, no `+cwt` (issuer catalogue section 7).'],
  });

const supportive002 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_RP_IA_Supportive_002',
    ...base(format),
    variants: [format, 'PA'],
    objective: "Verify that HTTP cache headers of the Provider's status list response, if it sets any, are consistent with the token's `ttl` and `exp`.",
    references: ['[TokenStatusList] sections 8.2 and 13.7', '[RFC 9111] section 4.2'],
    relevancy: relevancy.genericOptional,
    steps: [issueStep(format), fetchStep(format, [1], published(['sl-cache'], 'A cache that follows the response headers never serves the token longer than `ttl` or past `exp`; a response without caching-related headers passes.'))],
    comments: [
      'EUDI_optional. Token Status List has no cache-header rule for the Status Provider: section 8.2 says only that "If caching-related HTTP headers are present in the HTTP response, Relying Parties MUST prioritize the exp and ttl claims", and section 13.7 describes how Relying Parties use `ttl` and `exp`. A response without such headers therefore passes; headers that are present are checked because an HTTP cache between the Provider and a Relying Party does not read the token (spec review 2026-11-20, issuer catalogue section 8.3).',
    ],
  });

/** Number of credentials whose status URIs `PP_RP_IA_Supportive_003` compares (issuer catalogue section 5.2). */
export const PRIVACY_CREDENTIALS = 20;

const supportive003 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_RP_IA_Supportive_003',
    ...base(format),
    variants: [format, 'PA'],
    objective:
      'Verify that the status endpoint needs nothing that identifies the requester beyond the HTTP request itself: no tracking parameters in the status URIs, no cookie, and no status URI per credential.',
    references: ['[ARF] Annex 2, VCR_18 (note)', '[TokenStatusList] section 12.3'],
    relevancy: relevancy.specificRequired,
    steps: [
      ...Array.from({ length: PRIVACY_CREDENTIALS }, (_, i) =>
        i === 0 ? issueStep(format) : { ...issueStep(format), text: `As step 1, issuance ${i + 1} of ${PRIVACY_CREDENTIALS} (a new offer for \`SUBJ-1\`).` },
      ),
      fetchStep(
        format,
        Array.from({ length: PRIVACY_CREDENTIALS }, (_, i) => i + 1),
        published(['sl-anonymous', 'sl-uri-privacy'], `Across the ${PRIVACY_CREDENTIALS} credentials, the status URIs identify lists, not credentials or requesters.`),
        'The status URIs of all credentials are compared.',
      ),
    ],
    comments: [
      'What the Provider logs of a request cannot be observed over the interface; that part of the objective is for `PP_TB_005` (process review).',
      'OIDF `batch-issuance` covers this objective partly: a shared status list URI within one batch, as a WARNING (issuer catalogue section 7).',
    ],
  });

export const definitions = [supportive001('SD'), supportive002('SD'), supportive003('SD')];
