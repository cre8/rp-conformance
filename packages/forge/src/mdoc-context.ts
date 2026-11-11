// The callbacks @owf/mdoc needs to build and sign mdoc structures: WebCrypto ES256 for COSE_Sign1, SHA-2 digests, HKDF
// and HMAC. Only the issuing and presenting side uses them; the reference validator decodes and checks mdocs itself,
// so that each property is one named check (harness design section 7).
import { createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto';
import type { DigestAlgorithm } from '@owf/cose';
import { CoseKey, DeviceKey, type MdocContext, SignatureAlgorithm } from '@owf/mdoc';
import { parseCertificate } from '@owf/x509';
import { verifyEs256 } from './crypto';

const { subtle } = globalThis.crypto;

/** OIDs of the subject fields @owf/mdoc asks for (`C`, `ST`). */
const SUBJECT_FIELDS: Record<string, string> = { C: '2.5.4.6', ST: '2.5.4.8', O: '2.5.4.10', CN: '2.5.4.3' };

const DIGESTS: Record<DigestAlgorithm, string> = { 'SHA-256': 'sha256', 'SHA-384': 'sha384', 'SHA-512': 'sha512' };

/** Signs with ES256 (IEEE P1363 `r || s`, as COSE uses it) with the private key of a COSE key. */
async function signWithCoseKey(key: CoseKey, data: Uint8Array): Promise<Uint8Array> {
  const { kty, crv, x, y, d } = key.jwk as JsonWebKey;
  const jwk = { kty, crv, x, y, d };
  const privateKey = await subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, new Uint8Array(data)));
}

const hmacSha256 = (key: CoseKey | Uint8Array, data: Uint8Array) =>
  new Uint8Array(createHmac('sha256', key instanceof Uint8Array ? key : (key.k ?? key.privateKey)).update(data).digest());

const notUsed = (what: string) => () => {
  throw new Error(`${what} is not used by the harness`);
};

/** The `MdocContext` of the harness: ES256 on P-256 only, as HAIP section 7 and the test PKI use it. */
export const mdocContext: MdocContext = {
  fetch: (input, init) => fetch(input, init),
  crypto: {
    random: (length) => new Uint8Array(randomBytes(length)),
    digest: ({ digestAlgorithm, bytes }) => new Uint8Array(createHash(DIGESTS[digestAlgorithm]).update(bytes).digest()),
    hdkf: ({ digestAlgorithm, privateKey, salt, info }) =>
      new Uint8Array(hkdfSync(DIGESTS[digestAlgorithm ?? 'SHA-256'], privateKey, salt, info, 32)),
  },
  cose: {
    sign1: {
      sign: async ({ toBeSigned, key, algorithm }) => {
        if (algorithm !== SignatureAlgorithm.ES256) throw new Error(`COSE algorithm ${algorithm} is not supported`);
        return signWithCoseKey(key, toBeSigned);
      },
      verify: async ({ toBeVerified, signature, key }) => verifyEs256(key.jwk as JsonWebKey, toBeVerified, signature),
    },
    mac0: {
      authenticate: async ({ toBeAuthenticated, key }) => hmacSha256(key, toBeAuthenticated),
      verify: async ({ toBeAuthenticated, tag, key }) => {
        const expected = hmacSha256(key, toBeAuthenticated);
        return expected.length === tag.length && timingSafeEqual(expected, tag);
      },
    },
  },
  x509: {
    getSubjectNameField: ({ certificate, field }) => {
      const oid = SUBJECT_FIELDS[field];
      return parseCertificate(certificate).subject.attributes.filter((a) => a.type === oid).map((a) => a.value);
    },
    getPublicKey: async ({ certificate }) => {
      const jwk = parseCertificate(certificate).publicKey.jwk;
      if (!jwk) throw new Error('the certificate key is not supported');
      return CoseKey.fromJwk(jwk as Record<string, unknown>);
    },
    verifyCertificateChain: notUsed('x509.verifyCertificateChain'),
    getCertificateData: ({ certificate }) => {
      const parsed = parseCertificate(certificate);
      return {
        issuerName: parsed.issuer.rfc4514,
        subjectName: parsed.subject.rfc4514,
        serialNumber: parsed.serialNumber,
        thumbprint: createHash('sha256').update(parsed.der).digest('hex'),
        notBefore: parsed.notBefore,
        notAfter: parsed.notAfter,
        pem: parsed.pem,
      };
    },
  },
};

/** A COSE key with the private key of a P-256 JWK, for signing with ES256. */
export function coseSigningKey(privateJwk: JsonWebKey): CoseKey {
  const { kty, crv, x, y, d } = privateJwk;
  return CoseKey.fromJwk({ kty, crv, x, y, d, alg: 'ES256' });
}

/** The public part of a P-256 JWK as the device key of an MSO's `deviceKeyInfo`. */
export function deviceKeyOf(publicJwk: JsonWebKey): DeviceKey {
  const { kty, crv, x, y } = publicJwk;
  return DeviceKey.fromJwk({ kty, crv, x, y }) as DeviceKey;
}
