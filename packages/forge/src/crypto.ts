import { createHash, createPublicKey, randomBytes } from 'node:crypto';

const { subtle } = globalThis.crypto;

export interface EcKeyPair {
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  /** PKCS#8 PEM of the private key. */
  privateKeyPem: string;
}

/** Generates an ECDSA P-256 key pair (ES256). */
export async function generateEcKeyPair(): Promise<EcKeyPair> {
  const pair = (await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const publicJwk = await subtle.exportKey('jwk', pair.publicKey);
  const privateJwk = await subtle.exportKey('jwk', pair.privateKey);
  const pkcs8 = Buffer.from(await subtle.exportKey('pkcs8', pair.privateKey));
  return {
    publicJwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y },
    privateJwk,
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    privateKeyPem: toPem(pkcs8, 'PRIVATE KEY'),
  };
}

/** Signs with ES256 and returns the IEEE P1363 signature, as JWS and WebCrypto use it. */
export async function signEs256(privateKey: CryptoKey, data: Uint8Array | string): Promise<Uint8Array> {
  return new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, toBufferSource(data)));
}

export async function verifyEs256(publicJwk: JsonWebKey, data: Uint8Array | string, signature: Uint8Array): Promise<boolean> {
  const key = await subtle.importKey('jwk', publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  return subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, toBufferSource(signature), toBufferSource(data));
}

const toBufferSource = (data: Uint8Array | string): Uint8Array<ArrayBuffer> =>
  typeof data === 'string' ? new TextEncoder().encode(data) : new Uint8Array(data);

export const base64url = {
  encode: (data: Uint8Array | string) => Buffer.from(data).toString('base64url'),
  decode: (data: string) => new Uint8Array(Buffer.from(data, 'base64url')),
  decodeJson: <T = Record<string, unknown>>(data: string): T => JSON.parse(Buffer.from(data, 'base64url').toString('utf8')) as T,
};

export function sha256(data: Uint8Array | string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

export function randomSerial(): string {
  const bytes = randomBytes(16);
  bytes[0] &= 0x7f; // positive
  bytes[0] |= 0x01; // no leading zero octet
  return bytes.toString('hex');
}

export function toPem(der: Uint8Array, label: string): string {
  const b64 = Buffer.from(der).toString('base64');
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

/** SPKI PEM of a public JWK, for libraries that want PEM. */
export function publicJwkToPem(jwk: JsonWebKey): string {
  return createPublicKey({ key: jwk as never, format: 'jwk' }).export({ type: 'spki', format: 'pem' }).toString();
}

/** Signs a compact JWS with ES256: `header.payload.signature`. */
export async function signCompactJws(
  header: Record<string, unknown>,
  payload: Record<string, unknown> | string,
  privateKey: CryptoKey,
): Promise<string> {
  const encodedHeader = base64url.encode(JSON.stringify(header));
  const encodedPayload = base64url.encode(typeof payload === 'string' ? payload : JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = await signEs256(privateKey, signingInput);
  return `${signingInput}.${base64url.encode(signature)}`;
}
