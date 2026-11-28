// The data model checks of the PID Rulebook (ARF Annex 3.01) on what a PID Provider issued (issuer catalogue section
// 5.1.4, `DM_*`), one named check per rule so a forge-built PID with one defect fails exactly one of them:
//
// - `pid-type`: `vct` (SD-JWT VC, PID_14) or docType and namespace (mdoc, PID_04 to PID_06).
// - `pid-attributes`: the mandatory attributes and metadata are present, and every attribute of the Rulebook has the
//   name and encoding of its tables (JSON types for SD-JWT VC, CBOR types for mdoc, `full-date` as tag 1004).
// - `pid-unique`: an mdoc attribute identifier appears at most once per namespace (PID_11).
// - `pid-values`: the values equal the test subject's data, and the age attributes are valid at the start of the
//   validity period (PID_12, PID_19).
// - `pid-dates`: the issuance and expiry dates, if present, are consistent with the validity period (PID_13, PID_20).
// - `pid-extension`: claims outside the Rulebook belong to a documented domestic extension (PID_16).
// - `pid-formats`: the SD-JWT VC and the mdoc of one issuance carry the same values (ISSU_12, PID_02).
// - `pid-portrait`: after a portrait opt-out, the portrait is present and empty (PID_03).
//
// Every function returns the detail of a passed check or throws (`fail`); the caller records it with `CheckRecorder`.
import { ageOf, PID_SD_JWT_NAMES, type PidSubject, pidClaimsOf } from '@eudi-pcaf/core';
import { Tagged } from '@eudi-pcaf/forge';
import type { IssuerSignedElement } from './mdoc';
import { fail } from './status-list';

/** `vct` of the PID in SD-JWT VC format; a domestic type extends it in the `urn:eudi:pid:` namespace (PID_14). */
export const PID_VCT_BASE = 'urn:eudi:pid:1';
/** DocType and namespace of the PID in mdoc format (PID_04, PID_05). */
export const PID_MDOC_DOCTYPE = 'eu.europa.ec.eudi.pid.1';

const FULL_DATE = /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/;
const COUNTRY = /^[A-Z]{2}$/;
const DAY_MS = 24 * 60 * 60 * 1000;

type Encoding = (value: unknown) => string | undefined;

/** Describes why a value is not of an encoding, or undefined when it is. */
const isString: Encoding = (v) => (typeof v === 'string' ? undefined : `not a string (${typeof v})`);
const isCountry: Encoding = (v) => (typeof v === 'string' && COUNTRY.test(v) ? undefined : `not an ISO 3166-1 alpha-2 code (${JSON.stringify(v)})`);
const isUint: Encoding = (v) => (typeof v === 'number' && Number.isInteger(v) && v >= 0 ? undefined : `not an unsigned integer (${JSON.stringify(v)})`);
const isBool: Encoding = (v) => (typeof v === 'boolean' ? undefined : `not a boolean (${JSON.stringify(v)})`);
const isFullDateString: Encoding = (v) => (typeof v === 'string' && FULL_DATE.test(v) ? undefined : `not a full-date string YYYY-MM-DD (${JSON.stringify(v)})`);
const isPlace = (inner: Encoding): Encoding => (v) => {
  if (!v || typeof v !== 'object' || Array.isArray(v) || v instanceof Uint8Array) return 'not an object with country, region or locality';
  const entries = v instanceof Map ? [...v.entries()].map(([k, x]) => [String(k), x] as const) : Object.entries(v);
  if (!entries.some(([k]) => ['country', 'region', 'locality'].includes(k))) return 'has none of country, region and locality';
  for (const [k, x] of entries) {
    const problem = k === 'country' ? isCountry(x) : ['region', 'locality'].includes(k) ? inner(x) : undefined;
    if (problem) return `${k} is ${problem}`;
  }
  return undefined;
};
const isNonEmptyArrayOf = (inner: Encoding): Encoding => (v) => {
  if (!Array.isArray(v) || v.length === 0) return 'not a non-empty array';
  const index = v.findIndex((x) => inner(x));
  return index >= 0 ? `entry ${index + 1} is ${inner(v[index])}` : undefined;
};

/** CBOR `full-date`: tag 1004 over a `YYYY-MM-DD` text (RFC 8943, ISO/IEC 18013-5 section 7.2.1). */
const isCborFullDate: Encoding = (v) => {
  if (v instanceof Tagged && v.tag === 1004 && typeof v.value === 'string' && FULL_DATE.test(v.value)) return undefined;
  if (typeof v === 'string') return `a text string ${JSON.stringify(v)}, not a full-date (tag 1004)`;
  return `not a full-date (tag 1004)`;
};
/** CBOR `tdate` (tag 0) or `full-date` (tag 1004), as the Rulebook allows for the expiry and issuance dates. */
const isCborDate: Encoding = (v) =>
  v instanceof Tagged && v.tag === 0 && typeof v.value === 'string' && !Number.isNaN(Date.parse(v.value))
    ? undefined
    : isCborFullDate(v) && `${isCborFullDate(v)} or tdate (tag 0)`;
const isBstr: Encoding = (v) => (v instanceof Uint8Array ? undefined : `not a byte string`);
const isAgeOverMap: Encoding = (v) => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return 'not an object';
  for (const [k, x] of Object.entries(v)) {
    if (!/^\d{1,2}$/.test(k)) return `member ${k} is not an age`;
    if (isBool(x)) return `member ${k} is ${isBool(x)}`;
  }
  return undefined;
};
const isAddress: Encoding = (v) => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return 'not an object';
  for (const [k, x] of Object.entries(v)) {
    const problem = k === 'country' ? isCountry(x) : isString(x);
    if (problem) return `${k} is ${problem}`;
  }
  return undefined;
};

interface AttributeSpec {
  encoding: Encoding;
  mandatory?: true;
}

/** PID Rulebook chapter 4: the attributes of namespace `eu.europa.ec.eudi.pid.1` and their CBOR types. */
export const PID_MDOC_ATTRIBUTES: Record<string, AttributeSpec> = {
  family_name: { encoding: isString, mandatory: true },
  given_name: { encoding: isString, mandatory: true },
  birth_date: { encoding: isCborFullDate, mandatory: true },
  place_of_birth: { encoding: isPlace(isString), mandatory: true },
  nationality: { encoding: isNonEmptyArrayOf(isCountry), mandatory: true },
  expiry_date: { encoding: isCborDate, mandatory: true },
  issuing_authority: { encoding: isString, mandatory: true },
  issuing_country: { encoding: isCountry, mandatory: true },
  resident_address: { encoding: isString },
  resident_country: { encoding: isCountry },
  resident_state: { encoding: isString },
  resident_city: { encoding: isString },
  resident_postal_code: { encoding: isString },
  resident_street: { encoding: isString },
  resident_house_number: { encoding: isString },
  personal_administrative_number: { encoding: isString },
  portrait: { encoding: isBstr },
  family_name_birth: { encoding: isString },
  given_name_birth: { encoding: isString },
  sex: { encoding: isUint },
  email_address: { encoding: isString },
  mobile_phone_number: { encoding: isString },
  issuance_date: { encoding: isCborDate },
  document_number: { encoding: isString },
  issuing_jurisdiction: { encoding: isString },
  trust_anchor: { encoding: isString },
  age_in_years: { encoding: isUint },
  age_birth_year: { encoding: isUint },
};

/** PID Rulebook chapter 5: the claims of the PID in SD-JWT VC and their JSON types. */
export const PID_SD_JWT_ATTRIBUTES: Record<string, AttributeSpec> = {
  family_name: { encoding: isString, mandatory: true },
  given_name: { encoding: isString, mandatory: true },
  birthdate: { encoding: isFullDateString, mandatory: true },
  place_of_birth: { encoding: isPlace(isString), mandatory: true },
  nationalities: { encoding: isNonEmptyArrayOf(isCountry), mandatory: true },
  issuing_authority: { encoding: isString, mandatory: true },
  issuing_country: { encoding: isCountry, mandatory: true },
  address: { encoding: isAddress },
  personal_administrative_number: { encoding: isString },
  picture: { encoding: isString },
  birth_family_name: { encoding: isString },
  birth_given_name: { encoding: isString },
  sex: { encoding: isUint },
  email: { encoding: isString },
  phone_number: { encoding: isString },
  date_of_expiry: { encoding: isFullDateString },
  date_of_issuance: { encoding: isFullDateString },
  document_number: { encoding: isString },
  issuing_jurisdiction: { encoding: isString },
  trust_anchor: { encoding: isString },
  age_equal_or_over: { encoding: isAgeOverMap },
  age_in_years: { encoding: isUint },
  age_birth_year: { encoding: isUint },
};

/** Claims of the SD-JWT VC and JWT layer, not attributes of the PID. */
const SD_JWT_REGISTERED = new Set(['iss', 'sub', 'iat', 'nbf', 'exp', 'jti', 'aud', 'cnf', 'status', 'vct', 'vct#integrity', '_sd', '_sd_alg']);

const isAgeOver = (identifier: string) => /^age_over_\d{2}$/.test(identifier);

function checkAttributes(present: Map<string, unknown>, table: Record<string, AttributeSpec>, extra: (name: string, value: unknown) => string | undefined | null) {
  const missing = Object.entries(table)
    .filter(([name, spec]) => spec.mandatory && !present.has(name))
    .map(([name]) => name);
  if (missing.length) fail(`mandatory attribute(s) missing: ${missing.join(', ')}`);
  const problems: string[] = [];
  for (const [name, value] of present) {
    const spec = table[name];
    const problem = spec ? spec.encoding(value) : extra(name, value);
    if (problem) problems.push(`${name} is ${problem}`);
  }
  if (problems.length) fail(problems.join('; '));
  return `${Object.values(table).filter((s) => s.mandatory).length} mandatory attributes present; ${present.size} attributes with the Rulebook's encodings`;
}

// ---------------------------------------------------------------------------------------------------------------------
// SD-JWT VC (PID Rulebook chapter 5)

/** `pid-type` (SD-JWT VC, PID_14): `vct` is `urn:eudi:pid:1` or a domestic type in the `urn:eudi:pid:` namespace. */
export function checkPidVct(payload: Record<string, unknown>): string {
  const vct = payload.vct;
  if (vct === PID_VCT_BASE) return `vct ${vct}`;
  if (typeof vct === 'string' && vct.startsWith('urn:eudi:pid:')) return `vct ${vct}: a domestic type in the urn:eudi:pid: namespace`;
  return fail(`vct ${JSON.stringify(vct)} is neither ${PID_VCT_BASE} nor a domestic type in the urn:eudi:pid: namespace`);
}

/** The PID attributes of a disclosed SD-JWT VC: every claim except those of the JWT and SD-JWT VC layer. */
const sdJwtAttributes = (claims: Record<string, unknown>) => new Map(Object.entries(claims).filter(([name]) => !SD_JWT_REGISTERED.has(name)));

/** `pid-attributes` (SD-JWT VC, PID_17, PID_18): mandatory claims present, every Rulebook claim with its JSON type. */
export function checkPidSdJwtAttributes(claims: Record<string, unknown>): string {
  return checkAttributes(sdJwtAttributes(claims), PID_SD_JWT_ATTRIBUTES, () => null);
}

/**
 * `pid-extension` (SD-JWT VC, PID_16): claims outside the Rulebook belong to a domestic extension, which needs a domestic
 * `vct` with a published rulebook. Under `urn:eudi:pid:1` no claim outside the Rulebook may appear; under a domestic
 * `vct` the documentation of `documented` (claims of its Type Metadata or rulebook) must cover them.
 */
export function checkPidSdJwtExtension(claims: Record<string, unknown>, documented: string[] = []): string {
  const outside = [...sdJwtAttributes(claims).keys()].filter((name) => !PID_SD_JWT_ATTRIBUTES[name]);
  if (!outside.length) return 'no claim outside the PID Rulebook';
  if (claims.vct === PID_VCT_BASE) fail(`claim(s) ${outside.join(', ')} are not in the PID Rulebook, and vct ${PID_VCT_BASE} names no domestic extension`);
  const undocumented = outside.filter((name) => !documented.includes(name));
  if (undocumented.length) fail(`claim(s) ${undocumented.join(', ')} of the domestic type ${String(claims.vct)} are documented in no published rulebook`);
  return `claim(s) ${outside.join(', ')} documented for ${String(claims.vct)}`;
}

/** The start of the validity period of an SD-JWT VC, `nbf` or else `iat`, as a date. */
const sdJwtStart = (claims: Record<string, unknown>) => {
  const start = typeof claims.nbf === 'number' ? claims.nbf : claims.iat;
  if (typeof start !== 'number') fail('the credential has neither nbf nor iat');
  return new Date((start as number) * 1000);
};

/**
 * The age attributes a credential carries, as `{ over: { NN: value }, inYears, birthYear }`, checked against the birth
 * date at `at`: `age_over_NN` true exactly when the age is at least NN.
 */
function checkAges(ages: { over: Record<string, unknown>; inYears?: unknown; birthYear?: unknown }, birthDate: string, at: Date): string[] {
  const age = ageOf(birthDate, at);
  const problems: string[] = [];
  for (const [nn, value] of Object.entries(ages.over)) {
    if (value !== age >= Number(nn)) problems.push(`age over ${nn} is ${String(value)}, but the subject is ${age} at ${at.toISOString()}`);
  }
  if (ages.inYears !== undefined && ages.inYears !== age) problems.push(`age_in_years is ${String(ages.inYears)}, but the subject is ${age} at ${at.toISOString()}`);
  if (ages.birthYear !== undefined && ages.birthYear !== Number(birthDate.slice(0, 4))) problems.push(`age_birth_year is ${String(ages.birthYear)}, not ${birthDate.slice(0, 4)}`);
  return problems;
}

/**
 * The attributes of the test subject `pid-values` compares: the person's data. `issuing_authority` and
 * `issuing_country` are metadata of the Provider, checked for presence and encoding by `pid-attributes`.
 */
const SUBJECT_ATTRIBUTES = new Set(['family_name', 'given_name', 'birth_date', 'place_of_birth', 'nationality']);

/** Compares the subject's data with what was issued; returns a problem per differing attribute. */
function compareWithSubject(issued: Record<string, unknown>, subject: PidSubject, format: 'SD' | 'MD'): string[] {
  const problems: string[] = [];
  const personal = Object.fromEntries(Object.entries(subject).filter(([name]) => SUBJECT_ATTRIBUTES.has(name))) as unknown as PidSubject;
  for (const [name, value] of Object.entries(pidClaimsOf(personal, format))) {
    if (!(name in issued)) problems.push(`${name} is missing`);
    else if (!sameValue(issued[name], value)) problems.push(`${name} is ${JSON.stringify(issued[name])}, ${JSON.stringify(value)} expected`);
  }
  return problems;
}

/** Deep equality of JSON values; objects compare by their members regardless of order. */
export function sameValue(a: unknown, b: unknown): boolean {
  if (Array.isArray(a) || Array.isArray(b)) return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => sameValue(x, b[i]));
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    const [ka, kb] = [Object.keys(a).sort(), Object.keys(b).sort()];
    return sameValue(ka, kb) && ka.every((k) => sameValue((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
  }
  return a === b;
}

/** `pid-values` (SD-JWT VC, PID_19): the values equal the subject's, and the age claims are valid at `nbf` or `iat`. */
export function checkPidSdJwtValues(claims: Record<string, unknown>, subject: PidSubject): string {
  const start = sdJwtStart(claims);
  const problems = compareWithSubject(claims, subject, 'SD');
  problems.push(
    ...checkAges(
      { over: (claims.age_equal_or_over as Record<string, unknown> | undefined) ?? {}, inYears: claims.age_in_years, birthYear: claims.age_birth_year },
      subject.birth_date,
      start,
    ),
  );
  if (problems.length) fail(problems.join('; '));
  const ages = ['age_equal_or_over', 'age_in_years', 'age_birth_year'].filter((n) => n in claims);
  return `the subject's values; ${ages.length ? `${ages.join(', ')} valid at ${start.toISOString()}` : 'no age claims'}`;
}

/** The day a `full-date` names, as the instants it starts and ends (UTC). */
const dayOf = (date: string) => {
  const start = Date.parse(`${date}T00:00:00Z`);
  return { start, end: start + DAY_MS };
};

/**
 * The consistency rule of the issuance and expiry dates with the technical validity period (PID_13, PID_20): the
 * credential is not valid before the day it was issued, and not beyond the day the PID expires. `T_skew` applies to
 * both bounds.
 */
function checkDates(issuance: string | undefined, expiry: string | undefined, from: Date, until: Date, skewSeconds: number, names: [string, string, string, string]): string {
  const [issuanceName, expiryName, fromName, untilName] = names;
  const skew = skewSeconds * 1000;
  const problems: string[] = [];
  if (issuance !== undefined && dayOf(issuance).start > from.getTime() + skew) problems.push(`${issuanceName} ${issuance} lies after ${fromName} ${from.toISOString()}`);
  if (expiry !== undefined && dayOf(expiry).end < until.getTime() - skew) problems.push(`${untilName} ${until.toISOString()} lies after the end of ${expiryName} ${expiry}`);
  if (issuance !== undefined && expiry !== undefined && dayOf(issuance).start > dayOf(expiry).start) problems.push(`${issuanceName} ${issuance} lies after ${expiryName} ${expiry}`);
  if (problems.length) fail(problems.join('; '));
  const present = [issuance !== undefined && issuanceName, expiry !== undefined && expiryName].filter(Boolean);
  return present.length ? `${present.join(' and ')} consistent with ${fromName} and ${untilName}` : `neither ${issuanceName} nor ${expiryName} present`;
}

/** A date of the Rulebook as its `full-date` text: a `full-date` as it is, a `tdate` as the UTC day it falls on. */
const dayText = (value: unknown): string | undefined => {
  if (value instanceof Tagged) return value.tag === 0 ? new Date(String(value.value)).toISOString().slice(0, 10) : String(value.value);
  return typeof value === 'string' ? value.slice(0, 10) : undefined;
};

/** `pid-dates` (SD-JWT VC, PID_20): `date_of_issuance` and `date_of_expiry`, if present, against `iat`/`nbf` and `exp`. */
export function checkPidSdJwtDates(claims: Record<string, unknown>, skewSeconds: number): string {
  const start = sdJwtStart(claims);
  if (typeof claims.exp !== 'number') fail('the credential has no exp');
  return checkDates(
    dayText(claims.date_of_issuance),
    dayText(claims.date_of_expiry),
    start,
    new Date((claims.exp as number) * 1000),
    skewSeconds,
    ['date_of_issuance', 'date_of_expiry', typeof claims.nbf === 'number' ? 'nbf' : 'iat', 'exp'],
  );
}

/** `pid-portrait` (SD-JWT VC, PID_03): after the User opted out of the portrait, `picture` is present and empty. */
export function checkPidSdJwtPortraitOptOut(claims: Record<string, unknown>): string {
  if (!('picture' in claims)) fail('picture is missing; after an opt-out it is present as an empty string');
  if (claims.picture !== '') fail(`picture is not empty (${String(claims.picture).length} characters)`);
  return 'picture is an empty string';
}

// ---------------------------------------------------------------------------------------------------------------------
// mdoc (PID Rulebook chapter 4)

/** A domestic namespace of the PID (PID_06): `eu.europa.ec.eudi.pid.<country>.1`. */
const DOMESTIC_NAMESPACE = /^eu\.europa\.ec\.eudi\.pid\.[a-z]{2}\.\d+$/;

/**
 * `pid-type` (mdoc, PID_04 to PID_06): docType `eu.europa.ec.eudi.pid.1` in the document and the MSO, the Rulebook's
 * attributes in namespace `eu.europa.ec.eudi.pid.1`, and anything else only in a domestic namespace.
 */
export function checkPidDocType(docType: unknown, msoDocType: unknown, elements: IssuerSignedElement[]): string {
  if (docType !== PID_MDOC_DOCTYPE) fail(`docType ${JSON.stringify(docType)} is not ${PID_MDOC_DOCTYPE}`);
  if (msoDocType !== PID_MDOC_DOCTYPE) fail(`the MSO docType ${JSON.stringify(msoDocType)} is not ${PID_MDOC_DOCTYPE}`);
  const namespaces = [...new Set(elements.map((e) => e.namespace))];
  if (!namespaces.includes(PID_MDOC_DOCTYPE)) fail(`no element in namespace ${PID_MDOC_DOCTYPE}`);
  const foreign = namespaces.filter((ns) => ns !== PID_MDOC_DOCTYPE && !DOMESTIC_NAMESPACE.test(ns));
  if (foreign.length) fail(`namespace(s) ${foreign.join(', ')} are neither ${PID_MDOC_DOCTYPE} nor domestic (eu.europa.ec.eudi.pid.<cc>.<n>)`);
  const domestic = elements.filter((e) => e.namespace === PID_MDOC_DOCTYPE && !PID_MDOC_ATTRIBUTES[e.identifier] && !isAgeOver(e.identifier));
  if (domestic.length) fail(`element(s) ${domestic.map((e) => e.identifier).join(', ')} are not PID Rulebook attributes but in namespace ${PID_MDOC_DOCTYPE}, not a domestic one`);
  return `docType and namespace ${PID_MDOC_DOCTYPE}${namespaces.length > 1 ? `; domestic namespace(s) ${namespaces.filter((n) => n !== PID_MDOC_DOCTYPE).join(', ')}` : ''}`;
}

/** The elements of namespace `eu.europa.ec.eudi.pid.1`, the first of each identifier (`pid-unique` checks the rest). */
const pidElements = (elements: IssuerSignedElement[]) => {
  const map = new Map<string, unknown>();
  for (const e of elements) if (e.namespace === PID_MDOC_DOCTYPE && !map.has(e.identifier)) map.set(e.identifier, e.value);
  return map;
};

/** `pid-attributes` (mdoc, PID_08 to PID_10): mandatory attributes as issuer-signed items, each with its CBOR type. */
export function checkPidMdocAttributes(elements: IssuerSignedElement[]): string {
  return checkAttributes(pidElements(elements), PID_MDOC_ATTRIBUTES, (name, value) => (isAgeOver(name) ? isBool(value) : null));
}

/** `pid-unique` (mdoc, PID_11): every attribute identifier appears at most once per namespace. */
export function checkPidUnique(elements: IssuerSignedElement[]): string {
  const seen = new Set<string>();
  const twice = new Set<string>();
  for (const e of elements) {
    const key = `${e.namespace} ${e.identifier}`;
    if (seen.has(key)) twice.add(key);
    seen.add(key);
  }
  if (twice.size) fail(`element(s) appear more than once: ${[...twice].join(', ')}`);
  return `${elements.length} elements, each identifier once`;
}

/** An mdoc element value as the JSON value it stands for: dates as their text, maps as objects. */
const jsonValue = (value: unknown): unknown => {
  if (value instanceof Tagged) return dayText(value) ?? value.value;
  if (value instanceof Map) return Object.fromEntries([...value].map(([k, v]) => [String(k), jsonValue(v)]));
  if (Array.isArray(value)) return value.map(jsonValue);
  return value;
};

/** `pid-values` (mdoc, PID_12): the values equal the subject's, and the age attributes are valid at `validFrom`. */
export function checkPidMdocValues(elements: IssuerSignedElement[], subject: PidSubject, validFrom: Date): string {
  const issued = Object.fromEntries([...pidElements(elements)].map(([k, v]) => [k, jsonValue(v)]));
  const problems = compareWithSubject(issued, subject, 'MD');
  const over = Object.fromEntries(Object.entries(issued).filter(([k]) => isAgeOver(k)).map(([k, v]) => [k.slice('age_over_'.length), v]));
  problems.push(...checkAges({ over, inYears: issued.age_in_years, birthYear: issued.age_birth_year }, subject.birth_date, validFrom));
  if (problems.length) fail(problems.join('; '));
  const ages = Object.keys(issued).filter((k) => isAgeOver(k) || k === 'age_in_years' || k === 'age_birth_year');
  return `the subject's values; ${ages.length ? `${ages.join(', ')} valid at ${validFrom.toISOString()}` : 'no age attributes'}`;
}

/** `pid-dates` (mdoc, PID_13): `issuance_date` and `expiry_date`, if present, against `validFrom` and `validUntil`. */
export function checkPidMdocDates(elements: IssuerSignedElement[], validFrom: Date, validUntil: Date, skewSeconds: number): string {
  const map = pidElements(elements);
  return checkDates(dayText(map.get('issuance_date')), dayText(map.get('expiry_date')), validFrom, validUntil, skewSeconds, [
    'issuance_date',
    'expiry_date',
    'validFrom',
    'validUntil',
  ]);
}

/** `pid-portrait` (mdoc, PID_03): after the User opted out of the portrait, `portrait` is present as an empty `bstr`. */
export function checkPidMdocPortraitOptOut(elements: IssuerSignedElement[]): string {
  const map = pidElements(elements);
  if (!map.has('portrait')) fail('portrait is missing; after an opt-out it is present as an empty byte string');
  const portrait = map.get('portrait');
  if (!(portrait instanceof Uint8Array)) fail('portrait is not a byte string');
  if ((portrait as Uint8Array).length !== 0) fail(`portrait is not empty (${(portrait as Uint8Array).length} bytes)`);
  return 'portrait is an empty byte string';
}

/** The PID attributes of an mdoc as JSON values under their mdoc identifiers. */
export function pidMdocClaims(elements: IssuerSignedElement[]): Record<string, unknown> {
  return Object.fromEntries([...pidElements(elements)].map(([k, v]) => [k, v instanceof Uint8Array ? Buffer.from(v).toString('base64url') : jsonValue(v)]));
}

// ---------------------------------------------------------------------------------------------------------------------
// Both formats

/**
 * `pid-formats` (ISSU_12, PID_02): the SD-JWT VC and the mdoc of one issuance carry the same values. Every attribute of
 * the Rulebook present in either format is compared under the name of the other (`PID_SD_JWT_NAMES`); `age_over_NN`
 * corresponds to `age_equal_or_over.NN`. The portrait (`picture` and `portrait`) is compared only for presence, since
 * the SD-JWT VC carries it as a data URL.
 */
export function checkPidFormats(sdJwt: Record<string, unknown>, mdoc: Record<string, unknown>): string {
  const toSd = (name: string) => PID_SD_JWT_NAMES[name] ?? name;
  const problems: string[] = [];
  const compared: string[] = [];
  const mdocNames = Object.keys(mdoc).filter((n) => !isAgeOver(n));
  const sdNames = new Set(Object.keys(sdJwt).filter((n) => PID_SD_JWT_ATTRIBUTES[n] && n !== 'age_equal_or_over'));
  for (const name of mdocNames) {
    if (!PID_MDOC_ATTRIBUTES[name]) continue;
    const sdName = toSd(name);
    sdNames.delete(sdName);
    if (!(sdName in sdJwt)) {
      problems.push(`${name} is in the mdoc, ${sdName} not in the SD-JWT VC`);
      continue;
    }
    compared.push(name);
    if (name === 'portrait') continue;
    if (!sameValue(mdoc[name], sdJwt[sdName])) problems.push(`${name} ${JSON.stringify(mdoc[name])} in the mdoc, ${sdName} ${JSON.stringify(sdJwt[sdName])} in the SD-JWT VC`);
  }
  for (const sdName of sdNames) problems.push(`${sdName} is in the SD-JWT VC, not in the mdoc`);
  const over = (sdJwt.age_equal_or_over as Record<string, unknown> | undefined) ?? {};
  const mdocOver = Object.fromEntries(Object.entries(mdoc).filter(([k]) => isAgeOver(k)).map(([k, v]) => [String(Number(k.slice('age_over_'.length))), v]));
  for (const nn of new Set([...Object.keys(over).map((k) => String(Number(k))), ...Object.keys(mdocOver)])) {
    const sdValue = Object.entries(over).find(([k]) => String(Number(k)) === nn)?.[1];
    if (sdValue !== mdocOver[nn]) problems.push(`age over ${nn} is ${JSON.stringify(mdocOver[nn])} in the mdoc, ${JSON.stringify(sdValue)} in the SD-JWT VC`);
    else compared.push(`age over ${nn}`);
  }
  if (problems.length) fail(problems.join('; '));
  return `the same values in both formats: ${compared.join(', ')}`;
}
