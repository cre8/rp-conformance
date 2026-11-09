// Direct JOSE assembly for the fault layer: decode a compact JWS, change it, and sign it again, so strict libraries
// never stand between a valid artifact and its deliberate fault (harness design section 4.3).
import { base64url, signCompactJws } from './crypto';

export interface DecodedJws {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
}

export function decodeJws(compact: string): DecodedJws {
  const [header, payload, signature] = compact.split('.');
  return { header: base64url.decodeJson(header ?? ''), payload: base64url.decodeJson(payload ?? ''), signature: signature ?? '' };
}

/** Signs a changed copy of a compact JWS with ES256. */
export async function resignJws(
  compact: string,
  change: (jws: { header: Record<string, unknown>; payload: Record<string, unknown> }) => void,
  privateKey: CryptoKey,
): Promise<string> {
  const { header, payload } = structuredClone(decodeJws(compact));
  change({ header, payload });
  return signCompactJws(header, payload, privateKey);
}

/** Flips one bit in the middle of a base64url segment. */
export function flipBit(segment: string): string {
  const bytes = base64url.decode(segment);
  if (bytes.length === 0) throw new Error('nothing to flip');
  bytes[Math.floor(bytes.length / 2)] ^= 0x01;
  return base64url.encode(bytes);
}

/** Flips one bit in segment `index` of a compact serialisation (JWS: 2 is the signature; JWE: 3 ciphertext, 4 tag). */
export function flipBitInSegment(compact: string, index: number): string {
  const parts = compact.split('.');
  parts[index] = flipBit(parts[index] ?? '');
  return parts.join('.');
}
