// The attribute variants of `default_credential_pid` for the data model test cases (RP_WS_DM_IdentifyingData,
// RP_WS_DM_CredentialMetadata): the PID is issued, valid in every other respect, with other attributes. Each variant is
// a credential fault of the catalogue (FAULTS in @eudi-pcaf/core) that forgePresentation applies at issuance.
import type { FaultId } from '@eudi-pcaf/core';
import { DEFAULT_PID_MDOC_CLAIMS, type IssuedMdoc, issueMdoc, type MdocIssueOptions, PID_DOCTYPE, PID_NAMESPACE } from './mdoc';
import { DEFAULT_PID_CLAIMS, type IssuedSdJwtVc, issueSdJwtVc, PID_VCT, type PidIssueOptions } from './pid';

/** Names with characters outside Latin-1 (ISO/IEC 8859-1): Greek, and Polish `Ł` (U+0141). */
const UTF8_NAMES = { family_name: 'Παπαδοπούλου', given_name: 'Łucja' };

/** The mandatory attributes of the PID rulebook in SD-JWT VC encoding: those of `default_credential_pid` and the administrative ones. */
const MANDATORY_SD_JWT_VC = { ...DEFAULT_PID_CLAIMS, date_of_expiry: '2031-08-31', issuing_authority: 'DE', issuing_country: 'DE' };

const ADDRESS = { street_address: 'Heidestraße', house_number: '17', locality: 'Köln', postal_code: '51147', country: 'DE' };

interface SdJwtVcVariant {
  claims: Record<string, unknown>;
  /** The disclosure frame; default every top-level attribute selectively disclosable. */
  frame?: Record<string, unknown>;
}

const { family_name, given_name, birthdate } = DEFAULT_PID_CLAIMS;
const allDisclosable = (claims: Record<string, unknown>) => ({ _sd: Object.keys(claims) });

const SD_JWT_VC_VARIANTS: Partial<Record<FaultId, SdJwtVcVariant>> = {
  'credential.pid-mandatory-utf8': { claims: { ...MANDATORY_SD_JWT_VC, ...UTF8_NAMES } },
  'credential.pid-requested-only': { claims: { family_name, given_name, birthdate } },
  'credential.birthdate-integer': { claims: { ...DEFAULT_PID_CLAIMS, birthdate: 19640812 } },
  'credential.nationalities-string': { claims: { ...MANDATORY_SD_JWT_VC, nationalities: 'DE' } },
  'credential.age-over-18-true': { claims: { ...DEFAULT_PID_CLAIMS, age_equal_or_over: { '18': true } } },
  'credential.age-over-18-false': { claims: { ...DEFAULT_PID_CLAIMS, age_equal_or_over: { '18': false } } },
  'credential.age-over-18-false-required-true': { claims: { ...DEFAULT_PID_CLAIMS, age_equal_or_over: { '18': false } } },
  'credential.address-structured': {
    claims: { ...DEFAULT_PID_CLAIMS, address: ADDRESS },
    frame: { ...allDisclosable({ ...DEFAULT_PID_CLAIMS, address: ADDRESS }), address: { _sd: Object.keys(ADDRESS) } },
  },
  'credential.private-claim': {
    claims: { ...DEFAULT_PID_CLAIMS, rp_conformance_private_claim: 'unknown' },
    frame: allDisclosable(DEFAULT_PID_CLAIMS),
  },
};

const MDOC_VARIANTS: Partial<Record<FaultId, Record<string, unknown>>> = {
  'mdoc.pid-mandatory-utf8': { ...DEFAULT_PID_MDOC_CLAIMS, ...UTF8_NAMES },
  'mdoc.pid-requested-only': {
    family_name: DEFAULT_PID_MDOC_CLAIMS.family_name,
    given_name: DEFAULT_PID_MDOC_CLAIMS.given_name,
    birth_date: DEFAULT_PID_MDOC_CLAIMS.birth_date,
  },
  'mdoc.birth-date-integer': { ...DEFAULT_PID_MDOC_CLAIMS, birth_date: 19640812 },
  'mdoc.nationality-string': { ...DEFAULT_PID_MDOC_CLAIMS, nationality: 'DE' },
  'mdoc.age-over-18-true': { ...DEFAULT_PID_MDOC_CLAIMS, age_over_18: true },
  'mdoc.age-over-18-false': { ...DEFAULT_PID_MDOC_CLAIMS, age_over_18: false },
  'mdoc.age-over-18-false-required-true': { ...DEFAULT_PID_MDOC_CLAIMS, age_over_18: false },
};

/** Whether a credential fault is an attribute variant of the PID, applied when the PID is issued. */
export const isPidVariant = (fault: FaultId | undefined): fault is FaultId =>
  fault !== undefined && (fault in SD_JWT_VC_VARIANTS || fault in MDOC_VARIANTS);

/** Issues the attribute variant `fault` of `default_credential_pid` in SD-JWT VC format, as `issuePidSdJwtVc` issues the PID. */
export async function issuePidSdJwtVcVariant(fault: FaultId, options: PidIssueOptions): Promise<IssuedSdJwtVc> {
  const variant = SD_JWT_VC_VARIANTS[fault];
  if (!variant) throw new Error(`${fault} is no attribute variant of the PID in SD-JWT VC format`);
  return issueSdJwtVc({ ...options, vct: PID_VCT, claims: variant.claims, ...(variant.frame ? { disclosureFrame: variant.frame } : {}) });
}

/**
 * Issues the attribute variant `fault` of `default_credential_pid` in mdoc format, as `issuePidMdoc` issues the PID: the
 * `birth_date` and `expiry_date` given as `YYYY-MM-DD` text are encoded as `full-date`, a value of another type as it is.
 */
export async function issuePidMdocVariant(fault: FaultId, options: MdocIssueOptions): Promise<IssuedMdoc> {
  const claims = MDOC_VARIANTS[fault];
  if (!claims) throw new Error(`${fault} is no attribute variant of the PID in mdoc format`);
  const fullDates = new Set(['birth_date', 'expiry_date'].filter((name) => typeof claims[name] === 'string'));
  return issueMdoc({ ...options, docType: PID_DOCTYPE, namespace: PID_NAMESPACE, claims, fullDates });
}
