import { createHeaderAndPayload, StatusList, StatusListCwt } from '@owf/token-status-list';
import { COSE, COSE_ALG, x5chainValue } from './cbor';
import { signCompactJws } from './crypto';
import { coseSigningKey, mdocContext } from './mdoc-context';
import type { CertifiedKey } from './pki';

export interface StatusListTokenOptions {
  /** Signing certificate under the revocation anchor of the entity that issued the credential. */
  signer: CertifiedKey;
  /** `iss` of the token. */
  issuer: string;
  /** The URI the credential's status reference points to; becomes `sub` (Token Status List section 5.1). */
  uri: string;
  /** Status values by index. */
  statuses: number[];
  bits?: 1 | 2 | 4 | 8;
  now?: Date;
  /** Seconds until `exp`; default one day. */
  validitySeconds?: number;
  /** Seconds, `ttl` claim; default 300. */
  ttl?: number;
}

/** Header and payload of a Status List Token in JWT format (`typ` `statuslist+jwt`, ES256, `x5c`), before signing. */
export function statusListTokenParts(options: StatusListTokenOptions): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const now = Math.floor((options.now ?? new Date()).getTime() / 1000);
  const list = new StatusList(options.statuses, options.bits ?? 1);
  const { header, payload } = createHeaderAndPayload(
    list,
    {
      iss: options.issuer,
      sub: options.uri,
      iat: now,
      exp: now + (options.validitySeconds ?? 24 * 60 * 60),
      ttl: options.ttl ?? 300,
    },
    {
      alg: 'ES256',
      typ: 'statuslist+jwt',
      x5c: options.signer.chain.map((certificate) => Buffer.from(certificate.der).toString('base64')),
    } as never,
  );
  return { header: header as Record<string, unknown>, payload: payload as Record<string, unknown> };
}

/** Builds a Status List Token in JWT format (`typ` `statuslist+jwt`), signed with ES256 and `x5c`. */
export async function buildStatusListTokenJwt(options: StatusListTokenOptions): Promise<string> {
  const { header, payload } = statusListTokenParts(options);
  return signCompactJws(header, payload, options.signer.key.privateKey);
}

/** Media type of a Status List Token in CWT format (Token Status List section 5.2). */
export const STATUS_LIST_CWT_TYPE = 'application/statuslist+cwt';

/**
 * Builds a Status List Token in CWT format with @owf/token-status-list: a tagged COSE_Sign1 (ES256) whose protected
 * header carries `typ` (16) `application/statuslist+cwt` and the signer chain in `x5chain` (33), as ISO/IEC 18013-5
 * second edition section 12.3.6.3 requires, and whose claims set has `iss`, `sub` (the status `uri`), `iat`, `exp`,
 * `ttl` and `status_list`.
 */
export async function buildStatusListTokenCwt(options: StatusListTokenOptions): Promise<Uint8Array> {
  const now = options.now ?? new Date();
  const issuedAt = new Date(Math.floor(now.getTime() / 1000) * 1000);
  const token = new StatusListCwt({
    payload: {
      issuer: options.issuer,
      subject: options.uri,
      issuedAt,
      expirationTime: new Date(issuedAt.getTime() + (options.validitySeconds ?? 24 * 60 * 60) * 1000),
      statusList: new StatusList(options.statuses, options.bits ?? 1),
      timeToLive: options.ttl ?? 300,
    },
    protectedHeaders: new Map<number, unknown>([
      [COSE.alg, COSE_ALG.ES256],
      [COSE.typ, STATUS_LIST_CWT_TYPE],
      [COSE.x5chain, x5chainValue(options.signer.chain.map((certificate) => certificate.der))],
    ]),
  });
  return token.signAndEncode({ signingKey: coseSigningKey(options.signer.key.privateJwk) }, mdocContext.cose.sign1);
}
