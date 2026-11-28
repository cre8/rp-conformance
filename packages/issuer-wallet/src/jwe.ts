// Compact JWE with `alg` `ECDH-ES` (direct key agreement, RFC 7518 section 4.6) and `enc` `A128GCM` or `A256GCM`, for
// credential request and response encryption (OpenID4VCI 1.0 section 10). Built on node:crypto so the fault layer can
// send what a JOSE library would refuse (an unadvertised `enc`, a key off its curve) in the parameters it encrypts.
import { type CipherGCM, type DecipherGCM, createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, randomBytes } from 'node:crypto';
import { base64url } from '@eudi-pcaf/forge';

const KEY_BITS: Record<string, number> = { A128GCM: 128, A192GCM: 192, A256GCM: 256 };

const lengthPrefixed = (data: Uint8Array) => {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  return Buffer.concat([length, data]);
};

/** The Concat KDF of NIST SP 800-56A as RFC 7518 section 4.6.2 uses it, for keys of up to 256 bits. */
function concatKdf(z: Buffer, enc: string, apu: Uint8Array, apv: Uint8Array): Buffer {
  const bits = KEY_BITS[enc];
  if (!bits) throw new Error(`enc ${enc} is not an AES-GCM algorithm`);
  const counter = Buffer.from([0, 0, 0, 1]);
  const suppPub = Buffer.alloc(4);
  suppPub.writeUInt32BE(bits);
  const digest = createHash('sha256')
    .update(Buffer.concat([counter, z, lengthPrefixed(Buffer.from(enc)), lengthPrefixed(apu), lengthPrefixed(apv), suppPub]))
    .digest();
  return digest.subarray(0, bits / 8);
}

const publicOf = (jwk: JsonWebKey): JsonWebKey => ({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y });

/** An ephemeral P-256 key pair for a response encryption key, as JWKs. */
export function generateEncryptionKey(): { publicJwk: JsonWebKey; privateJwk: JsonWebKey } {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { publicJwk: publicOf(publicKey.export({ format: 'jwk' }) as JsonWebKey), privateJwk: privateKey.export({ format: 'jwk' }) as JsonWebKey };
}

/** Encrypts `plaintext` to the EC public key `recipient` (`ECDH-ES`, `enc`); `kid` goes into the protected header. */
export function encryptJwe(plaintext: string, recipient: JsonWebKey, enc: string, header: Record<string, unknown> = {}): string {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: String(recipient.crv) === 'P-384' ? 'secp384r1' : 'prime256v1' });
  const z = diffieHellman({ privateKey, publicKey: createPublicKey({ key: publicOf(recipient) as never, format: 'jwk' }) });
  const protectedHeader = { ...header, alg: 'ECDH-ES', enc, epk: publicOf(publicKey.export({ format: 'jwk' }) as JsonWebKey) };
  const encodedHeader = base64url.encode(JSON.stringify(protectedHeader));
  const cek = concatKdf(z, enc, new Uint8Array(), new Uint8Array());
  const iv = randomBytes(12);
  const cipher = createCipheriv(`aes-${cek.length * 8}-gcm`, cek, iv) as CipherGCM;
  cipher.setAAD(Buffer.from(encodedHeader));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return [encodedHeader, '', base64url.encode(iv), base64url.encode(ciphertext), base64url.encode(cipher.getAuthTag())].join('.');
}

/** Decrypts a compact JWE with `alg` `ECDH-ES` and an AES-GCM `enc` with the EC private key `recipient`. */
export function decryptJwe(compact: string, recipient: JsonWebKey): { header: Record<string, unknown>; plaintext: string } {
  const [encodedHeader, encryptedKey, iv, ciphertext, tag] = compact.split('.');
  if (tag === undefined) throw new Error('not a compact JWE (five parts)');
  const header = base64url.decodeJson(encodedHeader) as Record<string, unknown>;
  if (header.alg !== 'ECDH-ES') throw new Error(`JWE alg ${String(header.alg)}, not ECDH-ES`);
  if (encryptedKey) throw new Error('ECDH-ES (direct) carries no encrypted key');
  const enc = String(header.enc);
  const z = diffieHellman({
    privateKey: createPrivateKey({ key: recipient as never, format: 'jwk' }),
    publicKey: createPublicKey({ key: publicOf(header.epk as JsonWebKey) as never, format: 'jwk' }),
  });
  const decodeParty = (value: unknown) => (typeof value === 'string' ? base64url.decode(value) : new Uint8Array());
  const cek = concatKdf(z, enc, decodeParty(header.apu), decodeParty(header.apv));
  const decipher = createDecipheriv(`aes-${cek.length * 8}-gcm`, cek, base64url.decode(iv)) as DecipherGCM;
  decipher.setAAD(Buffer.from(encodedHeader));
  decipher.setAuthTag(base64url.decode(tag));
  const plaintext = Buffer.concat([decipher.update(base64url.decode(ciphertext)), decipher.final()]).toString('utf8');
  return { header, plaintext };
}
