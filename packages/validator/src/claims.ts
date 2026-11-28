// The `claims` check of the reference validator (RP_WS_DM_IdentifyingData, RP_WS_DM_CredentialMetadata): the disclosed
// claims satisfy the credential query, and the PID attributes have the data types of the PID rulebook.
import { Tagged } from '@eudi-pcaf/forge';
import { fail } from './status-list';

/** A claim of a DCQL credential query: its path and, optionally, the values it may have (OpenID4VP section 6.3). */
export interface RequestedClaim {
  path: (string | number | null)[];
  values?: (string | number | boolean)[];
}

const FULL_DATE = /^\d{4}-\d{2}-\d{2}$/;
const isFullDate = (value: unknown) => typeof value === 'string' && FULL_DATE.test(value) && !Number.isNaN(Date.parse(value));
const isText = (value: unknown) => typeof value === 'string' && value.length > 0;
const isTextArray = (value: unknown) => Array.isArray(value) && value.length > 0 && value.every(isText);
const isObject = (value: unknown) => value !== null && typeof value === 'object' && !Array.isArray(value) && !(value instanceof Uint8Array);

/** The PID attributes in SD-JWT VC encoding whose data type the PID rulebook fixes, with a test of that type. */
const SD_JWT_VC_PID_TYPES: Record<string, [string, (value: unknown) => boolean]> = {
  family_name: ['a string', isText],
  given_name: ['a string', isText],
  birthdate: ['a full-date string (ISO 8601-1, YYYY-MM-DD)', isFullDate],
  place_of_birth: ['an object', isObject],
  nationalities: ['an array of country codes', isTextArray],
  address: ['an object', isObject],
  age_equal_or_over: ['an object of booleans', (v) => isObject(v) && Object.values(v as object).every((b) => typeof b === 'boolean')],
  date_of_expiry: ['a full-date string (ISO 8601-1, YYYY-MM-DD)', isFullDate],
  issuing_authority: ['a string', isText],
  issuing_country: ['a string', isText],
};

/** A `full-date` of ISO/IEC 18013-5 (RFC 8943): tag 1004 over `YYYY-MM-DD`. */
const isCborFullDate = (value: unknown) => value instanceof Tagged && value.tag === 1004 && isFullDate(value.value);

/** The PID attributes in mdoc encoding, as raw CBOR values, whose data type the PID rulebook fixes. */
const MDOC_PID_TYPES: Record<string, [string, (value: unknown) => boolean]> = {
  family_name: ['a tstr', isText],
  given_name: ['a tstr', isText],
  birth_date: ['a full-date (tag 1004)', isCborFullDate],
  place_of_birth: ['a map', (v) => v instanceof Map],
  nationality: ['an array of country codes', isTextArray],
  expiry_date: ['a full-date (tag 1004)', isCborFullDate],
  issuing_authority: ['a tstr', isText],
  issuing_country: ['a tstr', isText],
};

/** The value at a claims path pointer (OpenID4VP section 7), or `undefined` when the path selects nothing. */
function valueAt(claims: Record<string, unknown>, path: RequestedClaim['path']): unknown {
  let value: unknown = claims;
  for (const segment of path) {
    if (segment === null) return Array.isArray(value) ? value : undefined;
    if (typeof segment === 'number') value = Array.isArray(value) ? value[segment] : undefined;
    else value = isObject(value) ? (value as Record<string, unknown>)[segment] : undefined;
    if (value === undefined) return undefined;
  }
  return value;
}

/**
 * Checks the disclosed claims against the credential query: every requested claim is disclosed (OpenID4VP sections 6.4
 * and 8.6) and has one of the values its `values` member allows (section 6.3). For a PID, every disclosed attribute the
 * PID rulebook types has that type: `pidTypes` `sd-jwt-vc` checks the JSON values, `mdoc` the raw CBOR values in
 * `raw` (by namespace), so a `full-date` must carry tag 1004. Throws the first defect; returns a detail otherwise.
 */
export function checkClaims(
  claims: Record<string, unknown>,
  requested: RequestedClaim[],
  pid?: { encoding: 'sd-jwt-vc' } | { encoding: 'mdoc'; namespace: string; raw: Record<string, Record<string, unknown>> },
): string {
  for (const claim of requested) {
    const value = valueAt(claims, claim.path);
    const name = claim.path.map(String).join('.');
    if (value === undefined) fail(`the requested claim ${name} is not disclosed`);
    if (claim.values && !claim.values.some((allowed) => allowed === value)) {
      fail(`the value ${JSON.stringify(value)} of ${name} is none of the values the query allows (${claim.values.map((v) => JSON.stringify(v)).join(', ')})`);
    }
  }
  if (pid?.encoding === 'sd-jwt-vc') {
    for (const [attribute, [type, test]] of Object.entries(SD_JWT_VC_PID_TYPES)) {
      if (attribute in claims && !test(claims[attribute])) fail(`the PID attribute ${attribute} is ${JSON.stringify(claims[attribute])}, not ${type}`);
    }
  }
  if (pid?.encoding === 'mdoc') {
    const elements = pid.raw[pid.namespace] ?? {};
    for (const [element, value] of Object.entries(elements)) {
      const [type, test] = MDOC_PID_TYPES[element] ?? (/^age_over_\d{2}$/.test(element) ? ['a bool', (v: unknown) => typeof v === 'boolean'] : []);
      if (test && !test(value)) fail(`the PID element ${element} is ${typeof value === 'object' ? value?.constructor?.name : JSON.stringify(value)}, not ${type}`);
    }
  }
  return `${requested.length} requested claim(s) disclosed`;
}
