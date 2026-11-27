import { ageOf, ATTESTATION_TEST_SUBJECTS, PID_TEST_SUBJECTS, pidClaimsOf, type TestSubject } from '@eudi-pcaf/core';

/**
 * The attribute values the adapter seeds for each test subject (issuer catalogue section 3.4, ICS-17). EUDIPLO takes the
 * claims with the offer (`credentialClaims`, type `inline`), so the adapter seeds the subject on every offer. The
 * Conformance Wallet compares every issued value with these.
 *
 * `SUBJ-1` has the values of `default_credential_pid` of the RP harness (`DEFAULT_PID_CLAIMS` of the forge) and the
 * PID Rulebook's issuance metadata; `SUBJ-2` is `SUBJ-1` with one attribute changed, `family_name`
 * (`SM_Revocation_008`).
 */
export const PID_SUBJECTS: Record<TestSubject, Record<string, unknown>> = {
  'SUBJ-1': {
    family_name: 'Mustermann',
    given_name: 'Erika',
    birthdate: '1964-08-12',
    place_of_birth: { locality: 'Berlin', country: 'DE' },
    nationalities: ['DE'],
    issuing_authority: 'DE',
    issuing_country: 'DE',
  },
  'SUBJ-2': {
    family_name: 'Gabler',
    given_name: 'Erika',
    birthdate: '1964-08-12',
    place_of_birth: { locality: 'Berlin', country: 'DE' },
    nationalities: ['DE'],
    issuing_authority: 'DE',
    issuing_country: 'DE',
  },
};

/** The claim definitions of the PID configuration (`fields`), every one selectively disclosable. */
export const PID_FIELDS = [
  { path: ['family_name'], type: 'string', mandatory: true, disclosable: true },
  { path: ['given_name'], type: 'string', mandatory: true, disclosable: true },
  { path: ['birthdate'], type: 'string', mandatory: true, disclosable: true },
  {
    path: ['place_of_birth'],
    type: 'object',
    mandatory: true,
    disclosable: true,
    children: [
      { path: ['locality'], type: 'string', disclosable: true },
      { path: ['country'], type: 'string', disclosable: true },
    ],
  },
  { path: ['nationalities'], type: 'array', mandatory: true, disclosable: true, children: [{ path: [null], type: 'string', disclosable: true }] },
  { path: ['issuing_authority'], type: 'string', mandatory: true, disclosable: true },
  { path: ['issuing_country'], type: 'string', mandatory: true, disclosable: true },
];

/** The claim definitions the SD-JWT VC PID configuration adds for the age claims and administrative dates. */
export const PID_SD_JWT_EXTRA_FIELDS = [
  { path: ['age_equal_or_over'], type: 'object', disclosable: true, children: [{ path: ['18'], type: 'boolean', disclosable: true }] },
  { path: ['age_in_years'], type: 'integer', disclosable: true },
  { path: ['age_birth_year'], type: 'integer', disclosable: true },
  { path: ['date_of_issuance'], type: 'string', disclosable: true },
  { path: ['date_of_expiry'], type: 'string', disclosable: true },
];

/** DocType and namespace of the PID in mdoc format (PID Rulebook chapter 4). */
export const PID_MDOC_NAMESPACE = 'eu.europa.ec.eudi.pid.1';

/**
 * A claim definition in the PID namespace. Its children carry the namespace too: EUDIPLO does not pass a field's
 * `namespace` on to its children, so it would publish their claims paths without it (`["nationality", null]`), and
 * since EUDIPLO/eudiplo#1636 (array steps published as `null`) its OID4VCI library then drops the whole mdoc
 * configuration as unknown (EUDIPLO/eudiplo#1650). The namespace of a child changes only
 * its published path.
 */
const mdocField = (name: string, type: string, mandatory = false, children?: Record<string, unknown>[], format?: 'date') => ({
  namespace: PID_MDOC_NAMESPACE,
  path: [name],
  type,
  ...(format ? { format } : {}),
  ...(mandatory ? { mandatory: true } : {}),
  ...(children ? { children: children.map((child) => ({ namespace: PID_MDOC_NAMESPACE, ...child })) } : {}),
});

/**
 * The claim definitions of the PID configuration in mdoc format, namespace `eu.europa.ec.eudi.pid.1` (PID Rulebook
 * chapter 4). The dates declare `format` `date` (EUDIPLO/eudiplo#1635), so EUDIPLO issues them as `full-date` (CBOR tag
 * 1004) as PID Rulebook section 3.1.2 requires; a release before it does not know the key, the adapter leaves it out
 * (`postWithoutUnknownKeys`) and the dates are text strings.
 */
export const PID_MDOC_FIELDS = [
  mdocField('family_name', 'string', true),
  mdocField('given_name', 'string', true),
  mdocField('birth_date', 'string', true, undefined, 'date'),
  mdocField('place_of_birth', 'object', true, [
    { path: ['locality'], type: 'string' },
    { path: ['country'], type: 'string' },
  ]),
  mdocField('nationality', 'array', true, [{ path: [null], type: 'string' }]),
  mdocField('expiry_date', 'string', true, undefined, 'date'),
  mdocField('issuing_authority', 'string', true),
  mdocField('issuing_country', 'string', true),
  mdocField('issuance_date', 'string', false, undefined, 'date'),
  mdocField('age_over_18', 'boolean'),
  mdocField('age_in_years', 'integer'),
  mdocField('age_birth_year', 'integer'),
];

const HOUR = 60 * 60 * 1000;
const dayOf = (ms: number) => new Date(ms).toISOString().slice(0, 10);

/**
 * The claims the adapter seeds for a subject and a format, with what the PID derives from the subject at issuance: the
 * age attributes at `now`, the issuance date and the expiry date of a credential living `lifetimeSeconds` (EUDIPLO
 * rounds the expiry up to the hour, `credential-time.util.ts`).
 */
export function pidClaimsFor(subject: TestSubject, format: 'SD' | 'MD', lifetimeSeconds: number, now = Date.now()): Record<string, unknown> {
  const person = PID_TEST_SUBJECTS[subject];
  const age = ageOf(person.birth_date, new Date(now));
  const issuance = dayOf(now);
  const expiry = dayOf(Math.ceil((now + lifetimeSeconds * 1000) / HOUR) * HOUR);
  const birthYear = Number(person.birth_date.slice(0, 4));
  if (format === 'SD') {
    return {
      ...PID_SUBJECTS[subject],
      age_equal_or_over: { '18': age >= 18 },
      age_in_years: age,
      age_birth_year: birthYear,
      date_of_issuance: issuance,
      date_of_expiry: expiry,
    };
  }
  return {
    ...pidClaimsOf(person, 'MD'),
    issuance_date: issuance,
    expiry_date: expiry,
    age_over_18: age >= 18,
    age_in_years: age,
    age_birth_year: birthYear,
  };
}

/** Issue 27: the namespace of `default_credential_A` in mdoc format (the forge's `CREDENTIAL_A_NAMESPACE`). */
export const ATTESTATION_NAMESPACE = 'test.rp-conformance.credential_a.1';

/** Issue 27: the claim definitions of `default_credential_A` in SD-JWT VC format, each selectively disclosable. */
export const ATTESTATION_SD_JWT_FIELDS = [
  { path: ['attribute_A'], type: 'number', mandatory: true, disclosable: true },
  { path: ['attribute_B'], type: 'string', mandatory: true, disclosable: true },
  { path: ['attribute_C'], type: 'string', mandatory: true, disclosable: true },
];

/** Issue 27: the same in mdoc format, namespace `test.rp-conformance.credential_a.1` (attribute_C a `full-date`, as for the PID). */
export const ATTESTATION_MDOC_FIELDS = [
  { namespace: ATTESTATION_NAMESPACE, path: ['attribute_A'], type: 'number', mandatory: true },
  { namespace: ATTESTATION_NAMESPACE, path: ['attribute_B'], type: 'string', mandatory: true },
  { namespace: ATTESTATION_NAMESPACE, path: ['attribute_C'], type: 'string', format: 'date', mandatory: true },
];

/** Issue 27: the claims of `default_credential_A` the adapter seeds for a subject (`ATTESTATION_TEST_SUBJECTS`). */
export function attestationClaimsFor(subject: TestSubject, _format: 'SD' | 'MD'): Record<string, unknown> {
  return { ...ATTESTATION_TEST_SUBJECTS[subject] };
}
