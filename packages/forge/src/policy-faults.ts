// Faults of the single objectives of issue 32: a Status List Token issued in the future or 30 days ago
// (RP_PP_SM_Revocation_014, decided by the policy the Relying Party declares), an SD-JWT VC issued in the future
// (RP_WS_SM_Validity_004, recorded only) and an MSO status element that names the certificate of the Status List Token
// (RP_PP_SM_Revocation_031, valid). The fault layer (faults.ts, faults-cose.ts) calls these first.
import type { FaultId } from '@eudi-pcaf/core';
import { type CborMap, coseValue, decodeCbor, decodeEmbedded, embedded, encodeCbor, readCose, sigStructure } from './cbor';
import { signEs256 } from './crypto';
import { resignJws } from './jose';
import type { CertifiedKey, TestEntity } from './pki';

const HOUR = 3600;
const DAY = 24 * HOUR;
/** The age of the old Status List Token of `RP_PP_SM_Revocation_014`, seconds. */
export const OLD_STATUS_LIST_AGE = 30 * DAY;
const seconds = (date: Date) => Math.floor(date.getTime() / 1000);
/** CWT claim keys (RFC 8392). */
const CWT = { exp: 4, iat: 6 } as const;

export const POLICY_FAULTS = {
  jwt: ['status-list.iat-future', 'status-list.iat-old'],
  cwt: ['status-list-cwt.iat-future', 'status-list-cwt.iat-old'],
  sdJwtCredential: ['credential.iat-future'],
  mdocCredential: ['mdoc.status-certificate'],
} as const satisfies Record<string, FaultId[]>;

const isOneOf = (list: readonly FaultId[], fault: FaultId) => list.includes(fault);
export const isPolicyStatusListFault = (fault: FaultId) => isOneOf(POLICY_FAULTS.jwt, fault);
export const isPolicyStatusListCwtFault = (fault: FaultId) => isOneOf(POLICY_FAULTS.cwt, fault);
export const isPolicyCredentialFault = (fault: FaultId) => isOneOf(POLICY_FAULTS.sdJwtCredential, fault);
export const isPolicyMdocFault = (fault: FaultId) => isOneOf(POLICY_FAULTS.mdocCredential, fault);

/** The `iat` and `exp` of the changed Status List Token, epoch seconds. */
function times(fault: FaultId, now: Date, skewSeconds: number): { iat: number; exp?: number } {
  return fault.endsWith('iat-future') ? { iat: seconds(now) + skewSeconds + HOUR } : { iat: seconds(now) - OLD_STATUS_LIST_AGE, exp: seconds(now) + DAY };
}

/** A Status List Token in JWT format with the `iat` of the fault, signed again with `signer`. */
export async function policyStatusListJwt(fault: FaultId, token: string, signer: CertifiedKey, now: Date, skewSeconds: number): Promise<string> {
  const { iat, exp } = times(fault, now, skewSeconds);
  return resignJws(
    token,
    ({ payload }) => {
      payload.iat = iat;
      if (exp !== undefined) payload.exp = exp;
    },
    signer.key.privateKey,
  );
}

/** A Status List Token in CWT format with the issued at claim of the fault, signed again with `signer`. */
export async function policyStatusListCwt(fault: FaultId, token: Uint8Array, signer: CertifiedKey, now: Date, skewSeconds: number): Promise<Uint8Array> {
  const { iat, exp } = times(fault, now, skewSeconds);
  const structure = readCose(decodeCbor(token));
  const claims = decodeCbor<CborMap>(structure.payload ?? new Uint8Array());
  claims.set(CWT.iat, iat);
  if (exp !== undefined) claims.set(CWT.exp, exp);
  const payload = encodeCbor(claims);
  const signature = await signEs256(signer.key.privateKey, sigStructure(structure.protectedBytes, payload));
  return encodeCbor(coseValue({ ...structure, payload, signature }));
}

/** An SD-JWT VC whose Issuer-signed JWT has the `iat` of the fault, signed again with `signer`. */
export async function policySdJwtCredential(sdJwt: string, signer: CertifiedKey, now: Date, skewSeconds: number): Promise<string> {
  const [jwt, ...rest] = sdJwt.split('~');
  const resigned = await resignJws(jwt, ({ payload }) => void (payload.iat = seconds(now) + skewSeconds + HOUR), signer.key.privateKey);
  return [resigned, ...rest].join('~');
}

/**
 * An mdoc whose MSO `status_list` entry also names the certificate that signs its Status List Token: the status list
 * signer of the issuing entity, under its revocation anchor. The MSO is signed again with `signer`.
 */
export async function policyMdocCredential(issuerSignedBytes: Uint8Array, signer: CertifiedKey, issuer: TestEntity | undefined): Promise<Uint8Array> {
  if (!issuer) throw new Error('mdoc.status-certificate needs the issuing entity');
  const issuerSigned = decodeCbor<CborMap>(issuerSignedBytes);
  const issuerAuth = readCose(issuerSigned.get('issuerAuth'));
  const mso = decodeEmbedded<CborMap>(decodeCbor(issuerAuth.payload ?? new Uint8Array()));
  const entry = (mso.get('status') as CborMap | undefined)?.get('status_list');
  if (!(entry instanceof Map)) throw new Error('the MSO has no status_list entry');
  entry.set('certificate', issuer.signers.revocation.certificate.der);
  const payload = encodeCbor(embedded(mso));
  const signature = await signEs256(signer.key.privateKey, sigStructure(issuerAuth.protectedBytes, payload));
  issuerSigned.set('issuerAuth', coseValue({ ...issuerAuth, payload, signature }));
  return encodeCbor(issuerSigned);
}
