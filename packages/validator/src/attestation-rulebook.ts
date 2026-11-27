// Issue 27: the data model checks of an attestation an Attestation Provider issues (issuer catalogue section 5.4,
// `AP_WS_DM_Rulebook`, `AP_WS_SM_Revocation_103`). The suite's attestation is FCAF `default_credential_A`, whose rulebook
// the FCAF defaults define: the type identifier (`vct` or doctype), the mandatory attributes `attribute_A` (positive
// number), `attribute_B` (non-empty Latin-1 string of at most 64 characters) and `attribute_C` (a date in the past,
// `full-date` in mdoc), and, as the suite's reading of that rulebook for ARB_30, each attribute selectively
// disclosable on its own and nothing else. The revocation method is the one of VCR_01 and VCR_02: a Token Status List
// reference, or a validity period of at most 24 hours.
import { ATTESTATION_DOCTYPE, ATTESTATION_VCT, type AttestationSubject } from '@eudi-pcaf/core';
import { base64url, Tagged } from '@eudi-pcaf/forge';
import type { IssuerSignedElement } from './mdoc';
import { fail } from './status-list';

const FULL_DATE = /^\d{4}-\d{2}-\d{2}$/;
const ATTRIBUTES = ['attribute_A', 'attribute_B', 'attribute_C'] as const;
/** Claims an SD-JWT VC must not make selectively disclosable (SD-JWT VC section 3.2.2.2). */
const NEVER_DISCLOSABLE = ['iss', 'nbf', 'exp', 'cnf', 'vct', 'vct#integrity', 'status', 'iat'];
const DAY = 24 * 60 * 60;

/** `attestation-type`: the `vct` (SD-JWT VC) or doctype (mdoc) is the one of `default_credential_A`. */
export function checkAttestationType(format: 'dc+sd-jwt' | 'mso_mdoc', type: unknown, elements: IssuerSignedElement[] = []): string {
  if (format === 'dc+sd-jwt') {
    if (type !== ATTESTATION_VCT) fail(`vct ${String(type)} is not ${ATTESTATION_VCT}`);
    return `vct ${ATTESTATION_VCT}`;
  }
  if (type !== ATTESTATION_DOCTYPE) fail(`docType ${String(type)} is not ${ATTESTATION_DOCTYPE}`);
  const outside = elements.filter((e) => e.namespace !== ATTESTATION_DOCTYPE);
  if (outside.length) fail(`element(s) outside the namespace ${ATTESTATION_DOCTYPE}: ${outside.map((e) => `${e.namespace} ${e.identifier}`).join(', ')}`);
  return `docType and namespace ${ATTESTATION_DOCTYPE}`;
}

/** A Latin-1 string (ISO/IEC 8859-1): every code point at most U+00FF. */
const isLatin1 = (value: string) => [...value].every((c) => (c.codePointAt(0) ?? 0) <= 0xff);

/** The value of `attribute_C` as its date text: a string in SD-JWT VC, a `full-date` (tag 1004) in mdoc. */
function dateOf(value: unknown, mdoc: boolean): string {
  if (mdoc) {
    if (!(value instanceof Tagged) || value.tag !== 1004 || typeof value.value !== 'string') return fail('attribute_C is not a full-date (CBOR tag 1004)');
    return value.value;
  }
  if (typeof value !== 'string') return fail(`attribute_C is ${typeof value}, not a date string`);
  return value;
}

/** The attributes of `default_credential_A`, from the disclosed SD-JWT VC claims or the mdoc elements of its namespace. */
export function attestationAttributes(source: Record<string, unknown> | IssuerSignedElement[]): Record<string, unknown> {
  if (!Array.isArray(source)) return source;
  return Object.fromEntries(source.filter((e) => e.namespace === ATTESTATION_DOCTYPE).map((e) => [e.identifier, e.value]));
}

/**
 * `attestation-attributes` (ISSU_25): `attribute_A` a positive number, `attribute_B` a non-empty Latin-1 string of at
 * most 64 characters, `attribute_C` a valid date in the past (`full-date` in mdoc).
 */
export function checkAttestationAttributes(source: Record<string, unknown> | IssuerSignedElement[], now = new Date()): string {
  const mdoc = Array.isArray(source);
  const values = attestationAttributes(source);
  const missing = ATTRIBUTES.filter((name) => values[name] === undefined);
  if (missing.length) fail(`mandatory attribute(s) missing: ${missing.join(', ')}`);
  const a = values.attribute_A;
  if (typeof a !== 'number' || !Number.isFinite(a) || a <= 0) fail(`attribute_A ${JSON.stringify(a)} is not a positive number`);
  const b = values.attribute_B;
  if (typeof b !== 'string' || b.length === 0 || b.length > 64 || !isLatin1(b)) fail(`attribute_B ${JSON.stringify(b)} is not a non-empty Latin-1 string of at most 64 characters`);
  const c = dateOf(values.attribute_C, mdoc);
  if (!FULL_DATE.test(c) || Number.isNaN(Date.parse(`${c}T00:00:00Z`)) || new Date(`${c}T00:00:00Z`).toISOString().slice(0, 10) !== c) fail(`attribute_C ${c} is not a valid full-date`);
  if (new Date(`${c}T00:00:00Z`) >= now) fail(`attribute_C ${c} is not in the past`);
  return `attribute_A ${a}, attribute_B (${(b as string).length} characters), attribute_C ${c}${mdoc ? ' (full-date)' : ''}`;
}

/** `attestation-values`: the attributes equal the test subject's data the adapter seeded (`SUBJ-1`, `SUBJ-2`). */
export function checkAttestationValues(source: Record<string, unknown> | IssuerSignedElement[], subject: AttestationSubject): string {
  const mdoc = Array.isArray(source);
  const values = attestationAttributes(source);
  const wrong = ATTRIBUTES.filter((name) => {
    const value = name === 'attribute_C' && mdoc && values[name] instanceof Tagged ? (values[name] as Tagged).value : values[name];
    return value !== subject[name];
  });
  if (wrong.length) fail(wrong.map((name) => `${name} is ${JSON.stringify(values[name] instanceof Tagged ? (values[name] as Tagged).value : values[name])}, expected ${JSON.stringify(subject[name])}`).join('; '));
  return `attribute_A, attribute_B and attribute_C equal the subject's`;
}

/**
 * `attestation-disclosure` (ARB_30, SD-JWT VC only): each attribute of `default_credential_A` is disclosed by a
 * disclosure of its own (the rulebook: MAY be disclosed selectively, so the Provider makes each one selectively
 * disclosable), and none of the claims SD-JWT VC section 3.2.2.2 forbids is selectively disclosable.
 */
export function checkAttestationDisclosure(payload: Record<string, unknown>, disclosures: string[]): string {
  const names: string[] = [];
  for (const disclosure of disclosures) {
    try {
      const decoded = JSON.parse(new TextDecoder().decode(base64url.decode(disclosure))) as unknown[];
      if (decoded.length === 3 && typeof decoded[1] === 'string') names.push(decoded[1]);
    } catch {
      fail('a disclosure is not base64url-encoded JSON');
    }
  }
  const plain = ATTRIBUTES.filter((name) => name in payload);
  if (plain.length) fail(`attribute(s) in the issuer-signed payload instead of a disclosure: ${plain.join(', ')}`);
  const missing = ATTRIBUTES.filter((name) => !names.includes(name));
  if (missing.length) fail(`attribute(s) without a disclosure of their own: ${missing.join(', ')}`);
  const twice = ATTRIBUTES.filter((name) => names.filter((n) => n === name).length > 1);
  if (twice.length) fail(`attribute(s) disclosed more than once: ${twice.join(', ')}`);
  const forbidden = names.filter((name) => NEVER_DISCLOSABLE.includes(name));
  if (forbidden.length) fail(`claim(s) that must not be selectively disclosable: ${forbidden.join(', ')}`);
  return `attribute_A, attribute_B and attribute_C each in a disclosure of its own; ${NEVER_DISCLOSABLE.filter((n) => n in payload).join(', ')} not disclosable`;
}

/**
 * `revocation-method` (VCR_01, VCR_02): the attestation references a Token Status List, or its validity period is at
 * most 24 hours (short-lived, no status). `periodSeconds` is the validity period; `statusList` whether it references one.
 */
export function checkRevocationMethod(statusList: boolean, periodSeconds: number | undefined): string {
  if (statusList) return 'Token Status List reference';
  if (periodSeconds !== undefined && periodSeconds <= DAY) return `short-lived: validity period ${periodSeconds} s, no status reference`;
  return fail(`no status reference, and the validity period (${periodSeconds === undefined ? 'unknown' : `${periodSeconds} s`}) exceeds 24 hours`);
}

/**
 * `qualified-service` (ISSU_08, ISSU_70, OIA_13): the signing certificate chains to the anchor of a granted service of
 * type `EAA/Q` (issuance of qualified electronic attestations of attributes) in a Trusted List reached via the LOTL.
 */
export function checkQualifiedService(service: { type: string; status?: string } | undefined, list: string | undefined): string {
  if (!service) return fail('the credential matched no service of the trust configuration');
  if (service.type !== 'http://uri.etsi.org/TrstSvc/Svctype/EAA/Q') fail(`the service is of type ${service.type}, not a qualified EAA service (EAA/Q)`);
  if (!/granted$/.test(service.status ?? '')) fail(`the qualified EAA service has status ${service.status ?? 'none'}, not granted`);
  return `granted EAA/Q service in ${list ?? 'a Trusted List'} reached via the LOTL`;
}
