// PP_WS_IA_Batch (`P-BATCH`, issuer catalogue section 5.1.2): one credential request with `batch_size` proofs, each
// signed by another attested key of one KA.
import { defineIssuerTestCase, type FormatVariant, type GrantVariant, ICS_BATCH_SIZE, relevancy } from '@eudi-pcaf/core';
import { iss, issuance, preconditions, rej, technologyOf } from '../../wording';
import { both, conf, FORMAT, faultStep, GRANT, MAIN, profileOf, ufPreconditions } from '../session';

const BATCH_SCN = '`CW-1` runs `SCN-I` for `SUBJ-1` without mutation, with a KA that attests `batch_size` keys (ICS-08) and a credential request with `batch_size` key proofs, each signed by another of these keys and carrying the KA.';
const batch = (format: FormatVariant, grant: GrantVariant) => issuance(format, grant, { batchSize: ICS_BATCH_SIZE });
const VCI = '[OpenID4VCI] section 8.2';

const batch001 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_Batch_001',
    variants: [format, grant],
    objective: 'Verify that a credential request with `batch_size` proofs returns that many credentials, each bound to a different key of the proofs.',
    references: ['[ARF] Annex 2, ISSU_43, ISSU_64', VCI],
    profile: profileOf(format, grant, 'P-BATCH'),
    relevancy: relevancy.specificRequired,
    technology: technologyOf(format),
    preconditions: preconditions.base,
    steps: [
      {
        text: BATCH_SCN,
        run: batch(format, grant),
        expect: both(iss(format), conf(['batch-size', 'batch-distinct-keys'], 'The Provider issues as many credentials as the request carries proofs, and the `cnf` key of each is the key of another proof.')),
      },
    ],
  });

const batch002 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_Batch_002',
    variants: [format, grant],
    objective: 'Verify that all credentials of a batch carry the same attribute values and the same validity period.',
    references: ['[ARF] Annex 2, ISSU_11a, ISSU_43, ISSU_51'],
    profile: profileOf(format, grant, 'P-BATCH'),
    relevancy: relevancy.specificRequired,
    technology: technologyOf(format),
    preconditions: preconditions.base,
    steps: [
      {
        text: BATCH_SCN,
        run: batch(format, grant),
        expect: conf(
          ['batch-same-claims', 'batch-same-validity'],
          'Every credential of the batch states the same claims about `SUBJ-1` (issuer-signed and disclosed, other than `cnf` and `status`), and the same `iat`, `nbf` and `exp`.',
        ),
      },
    ],
  });

const batch003 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_Batch_003_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Record how the PID Provider answers a credential request with more `jwt` proofs than its `batch_size`.',
    references: ['[OpenID4VCI] section 12.2.4'],
    profile: profileOf(format, grant, 'P-BATCH'),
    relevancy: relevancy.genericOptional,
    technology: technologyOf(format),
    preconditions: ufPreconditions(),
    steps: [
      faultStep(format, grant, 'batch.over-size', {
        codes: ['INFO'],
        text: 'Whether the Provider rejects the request (`invalid_proof` or `invalid_credential_request`) or issues the credentials is recorded; HTTP 5xx fails. OpenID4VCI 1.0 section 12.2.4 defines `batch_size` as "the maximum array size for the proofs parameter in a Credential Request", which the request exceeds, but states no rejection the Credential Issuer MUST give.',
      }),
    ],
    comments: [
      'Informational since the spec review of 2026-11-20 (issuer catalogue section 8.3): `batch_size` is defined in section 12.2.4, not section 8.2, and no MUST requires the Credential Issuer to reject a larger `proofs` array. Rejecting it is the hardened behaviour; EUDIPLO enforces it for `attestation` proofs (it counts `attested_keys`), not for `jwt` proofs.',
    ],
  });

const batch004 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_Batch_004_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that one invalid proof in a batch fails the whole request: no partial batch is issued.',
    references: [VCI],
    profile: profileOf(format, grant, 'P-BATCH'),
    relevancy: relevancy.genericRequired,
    technology: technologyOf(format),
    preconditions: ufPreconditions(),
    steps: [faultStep(format, grant, 'batch.one-bad-proof', rej('invalid_proof'))],
  });

const batch005 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_Batch_005_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that the same key twice in one batch does not give two credentials bound to the same key.',
    references: ['[ARF] Annex 2, ISSU_35 (d)'],
    profile: profileOf(format, grant, 'P-BATCH'),
    relevancy: relevancy.specificOptional,
    technology: technologyOf(format),
    preconditions: ufPreconditions(),
    steps: [
      faultStep(format, grant, 'batch.same-key-twice', {
        codes: ['INFO'],
        text: 'The Provider rejects the request (HTTP 4xx with an error object), or the report records how many credentials it issued and to how many distinct keys they are bound (catalogue: REJ or INFO).',
      }),
    ],
  });

const batch006 = (format: FormatVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_IA_Batch_006',
    variants: [format, 'AC'],
    objective: 'Verify that the first batch needs a single User authentication regardless of its size.',
    references: ['[ARF] Annex 2, ISSU_61'],
    profile: profileOf(format, 'AC', 'P-BATCH'),
    relevancy: relevancy.specificRequired,
    technology: technologyOf(format),
    preconditions: preconditions.base,
    steps: [
      {
        text: `${BATCH_SCN.replace('`SCN-I`', '`SCN-I` in the authorization code flow')} The adapter authenticates \`SUBJ-1\` once.`,
        run: issuance(format, 'AC', { batchSize: ICS_BATCH_SIZE }),
        expect: both(
          iss(format),
          conf(['batch-size', 'single-authentication'], 'One authorization gives the whole batch: the adapter authenticates `SUBJ-1` once, and the Provider issues `batch_size` credentials for it.'),
        ),
      },
    ],
    comments: ['Runs only in the authorization code flow (`AC`), where the User authenticates.'],
  });

export const definitions = [...[batch001, batch002, batch003, batch004, batch005].map((d) => d(FORMAT, GRANT)), batch006(FORMAT)];
