import { randomBytes } from 'node:crypto';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { base64url, sha256, signEs256 } from './crypto';
import type { CertifiedKey } from './pki';

/** `vct` of the PID in SD-JWT VC format (PID Rulebook, SD-JWT VC encoding). */
export const PID_VCT = 'urn:eudi:pid:1';

/** The attribute values of `default_credential_pid`: at least family name, given name and birth date. */
export const DEFAULT_PID_CLAIMS = {
  family_name: 'Mustermann',
  given_name: 'Erika',
  birthdate: '1964-08-12',
  place_of_birth: { locality: 'Berlin', country: 'DE' },
  nationalities: ['DE'],
} as const;

export const sdJwtHasher = (data: string | ArrayBuffer, alg: string) => {
  if (alg.toLowerCase() !== 'sha-256') throw new Error(`Unsupported hash algorithm ${alg}`);
  return sha256(typeof data === 'string' ? data : new Uint8Array(data));
};

export interface IssuedSdJwtVc {
  /** Compact SD-JWT VC without key binding, as the Test Issuer hands it to the Conformance Wallet. */
  compact: string;
  /** The issuer-signed payload before disclosures were hashed. */
  claims: Record<string, unknown>;
  header: Record<string, unknown>;
}

export interface PidIssueOptions {
  /** Signing certificate under the issuance anchor of the issuing entity, with its chain (no anchor). */
  signer: CertifiedKey;
  /** `iss` of the credential. */
  issuer: string;
  /** Public key of the Conformance Wallet the credential is bound to. */
  holderPublicJwk: JsonWebKey;
  /** The credential's status reference; omitted for `default_credential_pid_short`. */
  status?: { uri: string; idx: number };
  now?: Date;
  /** Seconds; default 30 days, `default_credential_pid` requires more than 24 hours. */
  validitySeconds?: number;
  claims?: Record<string, unknown>;
  /** SD-JWT VC media type in `typ`; `dc+sd-jwt` per SD-JWT VC. */
  typ?: string;
}

/**
 * Issues `default_credential_pid` in SD-JWT VC format: signed with ES256 under the issuer's signing
 * certificate carried in `x5c` (without the anchor), device-bound with `cnf.jwk`, every attribute
 * selectively disclosable, with a Token Status List reference.
 */
export async function issuePidSdJwtVc(options: PidIssueOptions): Promise<IssuedSdJwtVc> {
  const now = Math.floor((options.now ?? new Date()).getTime() / 1000);
  const claims = { ...DEFAULT_PID_CLAIMS, ...(options.claims ?? {}) };
  const payload = {
    iss: options.issuer,
    vct: PID_VCT,
    iat: now,
    nbf: now,
    exp: now + (options.validitySeconds ?? 30 * 24 * 60 * 60),
    cnf: { jwk: options.holderPublicJwk },
    ...(options.status ? { status: { status_list: options.status } } : {}),
    ...claims,
  };
  const header = {
    alg: 'ES256',
    typ: options.typ ?? 'dc+sd-jwt',
    x5c: options.signer.chain.map((certificate) => Buffer.from(certificate.der).toString('base64')),
  };
  const sdjwt = new SDJwtVcInstance({
    hasher: sdJwtHasher,
    hashAlg: 'sha-256',
    saltGenerator: (length) => randomBytes(length).toString('base64url'),
    signAlg: 'ES256',
    signer: async (data) => base64url.encode(await signEs256(options.signer.key.privateKey, data)),
    omitTyp: true,
  });
  const compact = await sdjwt.issue(payload, { _sd: Object.keys(claims) } as never, { header });
  return { compact, claims: payload, header };
}

export interface PresentOptions {
  /** The holder key the credential is bound to (`cnf.jwk`). */
  holderPrivateKey: CryptoKey;
  /** Top-level claims to disclose. */
  disclose: string[];
  /** KB-JWT `aud`: the Client Identifier of the Relying Party. */
  audience: string;
  nonce: string;
  now?: Date;
}

/** Presents an SD-JWT VC: discloses the given claims and appends a KB-JWT (RFC 9901 section 4.3). */
export async function presentSdJwtVc(compact: string, options: PresentOptions): Promise<string> {
  const sdjwt = new SDJwtVcInstance({
    hasher: sdJwtHasher,
    kbSignAlg: 'ES256',
    kbSigner: async (data) => base64url.encode(await signEs256(options.holderPrivateKey, data)),
  });
  const frame = Object.fromEntries(options.disclose.map((claim) => [claim, true]));
  return sdjwt.present(compact, frame, {
    kb: {
      payload: {
        iat: Math.floor((options.now ?? new Date()).getTime() / 1000),
        aud: options.audience,
        nonce: options.nonce,
      },
    },
  });
}
