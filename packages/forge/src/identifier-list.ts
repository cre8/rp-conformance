import { IdentifierList, IdentifierListCwt, MediaTypes } from '@owf/mdoc';
import { COSE, COSE_ALG, x5chainValue } from './cbor';
import { coseSigningKey, mdocContext } from './mdoc-context';
import type { CertifiedKey } from './pki';

/** Media type of an identifier list (ISO/IEC 18013-5 second edition section 12.3.6.4). */
export const IDENTIFIER_LIST_CWT_TYPE: string = MediaTypes.IdentifierListCwt;

export interface IdentifierListOptions {
  /** Signing certificate under the revocation anchor of the entity that issued the mdoc. */
  signer: CertifiedKey;
  issuer: string;
  /** The `uri` of the MSO's `identifier_list` entry; becomes `sub`. */
  uri: string;
  /** The identifiers of revoked MSOs. */
  identifiers: Uint8Array[];
  now?: Date;
  /** Seconds until `exp`; default one day. */
  validitySeconds?: number;
}

/**
 * Builds an identifier list in CWT format with @owf/mdoc: a tagged COSE_Sign1 (ES256) whose protected header carries
 * `typ` `application/identifierlist+cwt` and the signer chain in `x5chain`, and whose claims set has `iss`, `sub`,
 * `iat`, `exp` and `identifier_list` (65530).
 */
export async function buildIdentifierListCwt(options: IdentifierListOptions): Promise<Uint8Array> {
  const now = options.now ?? new Date();
  const issuedAt = new Date(Math.floor(now.getTime() / 1000) * 1000);
  const token = new IdentifierListCwt({
    payload: {
      issuer: options.issuer,
      uri: options.uri,
      issuedAt,
      expirationTime: new Date(issuedAt.getTime() + (options.validitySeconds ?? 24 * 60 * 60) * 1000),
      identifierList: IdentifierList.create({ identifiers: options.identifiers }),
    },
    protectedHeaders: new Map<number, unknown>([
      [COSE.alg, COSE_ALG.ES256],
      [COSE.typ, IDENTIFIER_LIST_CWT_TYPE],
      [COSE.x5chain, x5chainValue(options.signer.chain.map((certificate) => certificate.der))],
    ]),
  });
  return token.signAndEncode({ signingKey: coseSigningKey(options.signer.key.privateJwk) }, mdocContext.cose.sign1);
}
