import { createHeaderAndPayload, StatusList } from '@owf/token-status-list';
import { signCompactJws } from './crypto';
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
