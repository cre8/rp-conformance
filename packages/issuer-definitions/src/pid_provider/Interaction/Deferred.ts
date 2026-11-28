// PP_WS_IA_Deferred (`P-DEF`, issuer catalogue section 5.1.2): a deferred credential response, followed at the
// deferred credential endpoint.
import { defineIssuerTestCase, type FormatVariant, type GrantVariant, relevancy } from '@eudi-pcaf/core';
import { iss, issuance, preconditions, rej, technologyOf } from '../../wording';
import { both, conf, FORMAT, faultStep, GRANT, MAIN, profileOf, ufPreconditions } from '../session';

const DEFERRAL = 'The adapter can make the Provider defer an issuance for `SUBJ-1` and complete it later (ICS-10).';
const deferred = (format: FormatVariant, grant: GrantVariant) => issuance(format, grant, { deferred: true });
const SCN =
  '`CW-1` runs `SCN-I` for `SUBJ-1` without mutation. The credential response is deferred (HTTP 202 with `transaction_id` and `interval`); `CW-1` polls the deferred credential endpoint with the `transaction_id` and its access token, at the `interval`, until the credential arrives.';

const deferred001 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_Deferred_001',
    variants: [format, grant],
    objective: 'Verify that a deferred response carries `transaction_id` and `interval`, and that polling returns `issuance_pending` and then the credential.',
    references: ['[OpenID4VCI] section 9'],
    profile: profileOf(format, grant, 'P-DEF'),
    relevancy: relevancy.genericOptional,
    technology: technologyOf(format),
    preconditions: [...preconditions.base, DEFERRAL],
    steps: [
      {
        text: `${SCN} The adapter completes the issuance after the first poll answered \`issuance_pending\`.`,
        run: deferred(format, grant),
        expect: both(iss(format), conf(['deferred-pending'], 'The credential response is HTTP 202 with `transaction_id` and `interval`; at least one poll answers `issuance_pending`, and a later one the credential.')),
      },
    ],
  });

const deferred002 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_Deferred_002_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that the PID Provider rejects an unknown, or already redeemed, `transaction_id`.',
    references: ['[OpenID4VCI] section 9.3'],
    profile: profileOf(format, grant, 'P-DEF'),
    relevancy: relevancy.genericOptional,
    technology: technologyOf(format),
    preconditions: ufPreconditions(DEFERRAL),
    steps: [
      faultStep(format, grant, 'deferred.transaction-id-unknown', rej('invalid_transaction_id'), { deferred: true }),
      { text: SCN, run: deferred(format, grant), expect: iss(format) },
      {
        text: '`CW-1` sends the deferred credential request of step 2 again, with its `transaction_id`, already redeemed, and its access token.',
        run: { kind: 'token-reuse', artifact: 'transaction-id', ofStep: 2 },
        expect: rej('invalid_transaction_id'),
      },
    ],
  });

const deferred003 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_Deferred_003_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that the PID Provider rejects a `transaction_id` redeemed with the access token of another session.',
    references: ['[OpenID4VCI] section 9.1'],
    profile: profileOf(format, grant, 'P-DEF'),
    relevancy: relevancy.genericOptional,
    technology: technologyOf(format),
    preconditions: ufPreconditions(DEFERRAL, 'Wallet Unit `CW-2` of `WP-A` (section 3.4).'),
    steps: [
      {
        text: '`CW-2` runs `SCN-I` for `SUBJ-1` without mutation (another session; its access token is used in step 2).',
        run: { ...deferred(format, grant), walletUnit: 'CW-2' },
        expect: iss(format),
      },
      faultStep(format, grant, 'deferred.access-token-foreign', rej(), { deferred: true }),
    ],
  });

export const definitions = [deferred001, deferred002, deferred003].map((d) => d(FORMAT, GRANT));
