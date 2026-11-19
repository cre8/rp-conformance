// The presentation the Conformance Wallet builds for a request (harness design section 4.3): an SD-JWT VC with a KB-JWT
// (RFC 9901 section 4.3), or an mdoc DeviceResponse with a device signature over the SessionTranscript of OpenID4VP
// Appendix B.2.6, valid or with one presentation fault. The Conformance Wallet and the self-validation build it with the
// same function, so the self-validated presentations are the ones the Relying Party receives.
import { createHmac, generateKeyPairSync, type KeyObject, randomBytes, sign as nodeSign } from 'node:crypto';
import { type FaultId, faultInfo } from '@rp-conformance/core';
import { type CborMap, COSE_ALG, coseValue, decodeCbor, encodeCbor, readCose } from './cbor';
import { base64url, type EcKeyPair, generateEcKeyPair, publicJwkToPem, sha256, signCompactJws } from './crypto';
import { flipBitInBytes, OTHER_DOCTYPE } from './faults-cose';
import { decodeJws, flipBitInSegment, resignJws } from './jose';
import { encodeDeviceResponse, jwkThumbprint, type Oid4vpHandover, PID_NAMESPACE, presentMdoc } from './mdoc';
import { presentSdJwtVc } from './pid';

/** A credential the Conformance Wallet holds: an SD-JWT VC (compact, without KB-JWT) or an mdoc's `IssuerSigned` (CBOR). */
export type HeldCredential = { format: 'dc+sd-jwt'; value: string } | { format: 'mso_mdoc'; value: Uint8Array; docType?: string };

/** A key pair on secp256k1, as Node.js key objects: WebCrypto has no secp256k1. */
export interface Secp256k1KeyPair {
  publicJwk: JsonWebKey;
  privateKey: KeyObject;
}

/** A Conformance Wallet key on secp256k1, for the device authentication faults with `ES256K`. */
export function generateSecp256k1KeyPair(): Secp256k1KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const { kty, crv, x, y } = publicKey.export({ format: 'jwk' });
  return { publicJwk: { kty, crv, x, y }, privateKey };
}

/** Signs with ES256K and returns the IEEE P1363 signature. */
const signEs256k = (key: Secp256k1KeyPair, data: Uint8Array | string) =>
  new Uint8Array(nodeSign('sha256', typeof data === 'string' ? Buffer.from(data) : data, { key: key.privateKey, dsaEncoding: 'ieee-p1363' }));

/** What a presentation is bound to: the request's `nonce`, its audience and, for an mdoc, its SessionTranscript. */
export interface PresentationBinding {
  /** KB-JWT `aud`: the Client Identifier (redirects), or `origin:<origin>` (DC API, OpenID4VP Appendix A.4). */
  audience: string;
  /** The `client_id` of the request, when it has one. */
  clientId?: string;
  nonce: string;
  handover: Oid4vpHandover;
  /** Thumbprint of the request's encryption key, for the SessionTranscript of an encrypted response. */
  jwkThumbprint: Uint8Array | null;
}

/** What the request asks for: the claims of an SD-JWT VC to disclose, the elements of an mdoc by namespace. */
export interface RequestedClaims {
  disclose: string[];
  elements: Record<string, string[]>;
}

export interface PresentationKeys {
  /** The P-256 key the credential is bound to. */
  holder: EcKeyPair;
  /** The secp256k1 key a credential is bound to for an `ES256K` fault. */
  secp256k1?: Secp256k1KeyPair;
}

export interface PresentationOptions {
  /** A fault at the point `presentation`; `presentation.replay` is applied by the caller, which holds the earlier presentation. */
  fault?: FaultId;
  /** `T_skew`, seconds. */
  skewSeconds: number;
  /** `T_kb`, seconds. */
  kbMaxAgeSeconds: number;
  now?: Date;
}

const HOUR = 3600;
const OTHER_ORIGIN = 'https://other.example';

/** The `x509_hash` Client Identifier of a Relying Party that is not the one of the request. */
const otherClientId = () => `x509_hash:${base64url.encode(sha256(randomBytes(32)))}`;

/**
 * Builds the `vp_token` entry for a request: the SD-JWT VC with the requested disclosures and a KB-JWT, or the
 * DeviceResponse (base64url) with the requested elements; then applies `options.fault`.
 */
export async function buildPresentation(
  held: HeldCredential,
  requested: RequestedClaims,
  binding: PresentationBinding,
  keys: PresentationKeys,
  options: PresentationOptions,
): Promise<string> {
  const { fault } = options;
  if (fault) {
    const info = faultInfo(fault);
    if (info.point !== 'presentation') throw new Error(`fault ${fault} does not apply to the presentation`);
    if (fault === 'presentation.replay') throw new Error('presentation.replay sends the presentation of an earlier step');
    if (info.format && info.format !== held.format) throw new Error(`fault ${fault} applies to ${info.format}, not ${held.format}`);
    if (info.flow && info.flow !== binding.handover.flow) throw new Error(`fault ${fault} applies to the ${info.flow} flow`);
  }
  return held.format === 'mso_mdoc'
    ? presentMdocWithFault(held.value, requested, binding, keys, fault, held.docType)
    : presentSdJwtVcWithFault(held.value, requested, binding, keys, options);
}

async function presentSdJwtVcWithFault(
  credential: string,
  requested: RequestedClaims,
  binding: PresentationBinding,
  keys: PresentationKeys,
  options: PresentationOptions,
): Promise<string> {
  const now = options.now ?? new Date();
  const valid = await presentSdJwtVc(credential, {
    holderPrivateKey: keys.holder.privateKey,
    disclose: requested.disclose,
    audience: binding.audience,
    nonce: binding.nonce,
    now,
  });
  const { fault } = options;
  if (!fault) return valid;
  const cut = valid.lastIndexOf('~') + 1;
  const sdJwt = valid.slice(0, cut);
  const kbJwt = valid.slice(cut);
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const resign = async (change: Parameters<typeof resignJws>[1], key = keys.holder.privateKey) => sdJwt + (await resignJws(kbJwt, change, key));
  /** The KB-JWT's signing input with header members replaced, for an unsigned, HMAC or ES256K KB-JWT. */
  const unsigned = (header: Record<string, unknown>) => {
    const decoded = decodeJws(kbJwt);
    return `${base64url.encode(JSON.stringify({ ...decoded.header, ...header }))}.${base64url.encode(JSON.stringify(decoded.payload))}`;
  };
  switch (fault) {
    case 'presentation.kb-nonce-other':
      return resign(({ payload }) => void (payload.nonce = base64url.encode(randomBytes(16))));
    case 'presentation.kb-aud-other-client':
      return resign(({ payload }) => void (payload.aud = otherClientId()));
    case 'presentation.kb-aud-no-prefix': {
      if (!binding.audience.startsWith('x509_hash:')) throw new Error(`the Client Identifier ${binding.audience} has no x509_hash: prefix to remove`);
      return resign(({ payload }) => void (payload.aud = binding.audience.slice('x509_hash:'.length)));
    }
    case 'presentation.kb-aud-missing':
      return resign(({ payload }) => void delete payload.aud);
    case 'presentation.kb-aud-array':
      return resign(({ payload }) => void (payload.aud = [binding.audience]));
    case 'presentation.kb-nonce-missing':
      return resign(({ payload }) => void delete payload.nonce);
    case 'presentation.kb-iat-nan': {
      // JSON has no NaN (RFC 8259 section 6): the payload is written by hand and the holder key signs those bytes.
      const { header, payload } = decodeJws(kbJwt);
      const json = JSON.stringify({ ...payload, iat: 0 }).replace('"iat":0', '"iat":NaN');
      return sdJwt + (await signCompactJws(header, json, keys.holder.privateKey));
    }
    case 'presentation.kb-aud-client-id': {
      if (!binding.clientId) throw new Error('the request has no client_id');
      return resign(({ payload }) => void (payload.aud = binding.clientId));
    }
    case 'presentation.kb-aud-other-origin':
      return resign(({ payload }) => void (payload.aud = `origin:${OTHER_ORIGIN}`));
    case 'presentation.kb-iat-past':
      return resign(({ payload }) => void (payload.iat = nowSeconds - options.kbMaxAgeSeconds - HOUR));
    case 'presentation.kb-iat-future':
      return resign(({ payload }) => void (payload.iat = nowSeconds + options.skewSeconds + HOUR));
    case 'presentation.kb-signature-bitflip':
      return sdJwt + flipBitInSegment(kbJwt, 2);
    case 'presentation.kb-other-key':
      return resign(() => undefined, (await generateEcKeyPair()).privateKey);
    case 'presentation.no-kb-jwt':
      return sdJwt;
    case 'presentation.kb-typ-missing':
      return resign(({ header }) => void delete header.typ);
    case 'presentation.kb-typ-jwt':
      return resign(({ header }) => void (header.typ = 'JWT'));
    case 'presentation.kb-sd-hash-other': {
      const parts = sdJwt.split('~');
      if (parts.length < 3) throw new Error('the presentation has no disclosure to leave out');
      const shorter = [...parts.slice(0, -2), ''].join('~');
      return resign(({ payload }) => void (payload.sd_hash = base64url.encode(sha256(shorter))));
    }
    case 'presentation.kb-alg-none':
      return `${sdJwt}${unsigned({ alg: 'none' })}.`;
    case 'presentation.kb-hs256-public-key': {
      const cnf = decodeJws(sdJwt.split('~')[0] ?? '').payload.cnf as { jwk?: JsonWebKey } | undefined;
      if (!cnf?.jwk) throw new Error('the credential has no cnf.jwk');
      const input = unsigned({ alg: 'HS256' });
      return `${sdJwt}${input}.${base64url.encode(createHmac('sha256', publicJwkToPem(cnf.jwk)).update(input).digest())}`;
    }
    case 'presentation.kb-es256k': {
      if (!keys.secp256k1) throw new Error('presentation.kb-es256k needs the secp256k1 key the credential is bound to');
      const input = unsigned({ alg: 'ES256K' });
      return `${sdJwt}${input}.${base64url.encode(signEs256k(keys.secp256k1, input))}`;
    }
    default:
      throw new Error(`fault ${fault} is not implemented for SD-JWT VC`);
  }
}

async function presentMdocWithFault(
  issuerSigned: Uint8Array,
  requested: RequestedClaims,
  binding: PresentationBinding,
  keys: PresentationKeys,
  fault?: FaultId,
  docType?: string,
): Promise<string> {
  let handover = binding.handover;
  let { nonce, jwkThumbprint: thumbprint } = binding;
  let holderPrivateKey = keys.holder.privateKey;
  let deviceNameSpaces: Map<string, Map<string, unknown>> | undefined;
  let deviceSigner: Parameters<typeof presentMdoc>[1]['deviceSigner'];
  let deviceAuthentication: Parameters<typeof presentMdoc>[1]['deviceAuthentication'];
  const redirect = () => {
    if (handover.flow !== 'redirect') throw new Error(`fault ${fault} applies to the redirect flow`);
    return handover;
  };
  switch (fault) {
    case undefined:
    case 'presentation.device-signature-bitflip':
    case 'presentation.no-device-auth':
    case 'presentation.device-signature-missing':
      break;
    case 'presentation.transcript-nonce':
      nonce = base64url.encode(randomBytes(16));
      break;
    case 'presentation.transcript-client-id':
      handover = { ...redirect(), clientId: otherClientId() };
      break;
    case 'presentation.transcript-client-id-no-prefix': {
      const { clientId } = redirect();
      if (!clientId.startsWith('x509_hash:')) throw new Error(`the Client Identifier ${clientId} has no x509_hash: prefix to remove`);
      handover = { ...redirect(), clientId: clientId.slice('x509_hash:'.length) };
      break;
    }
    case 'presentation.transcript-response-uri': {
      const uri = new URL(redirect().responseUri);
      uri.pathname = uri.pathname.replace(/\/?$/, '/other');
      handover = { ...redirect(), responseUri: uri.href };
      break;
    }
    case 'presentation.transcript-jwk-thumbprint':
      thumbprint = await jwkThumbprint((await generateEcKeyPair()).publicJwk);
      break;
    case 'presentation.transcript-jwk-thumbprint-null':
      thumbprint = null;
      break;
    case 'presentation.transcript-origin':
      if (handover.flow !== 'dc-api') throw new Error(`fault ${fault} applies to the dc-api flow`);
      handover = { flow: 'dc-api', origin: OTHER_ORIGIN };
      break;
    case 'presentation.transcript-origin-prefixed':
      if (handover.flow !== 'dc-api') throw new Error(`fault ${fault} applies to the dc-api flow`);
      handover = { flow: 'dc-api', origin: `origin:${handover.origin}` };
      break;
    case 'presentation.device-signature-doctype-other':
      deviceAuthentication = { docType: OTHER_DOCTYPE };
      break;
    case 'presentation.device-signature-not-detached':
      deviceAuthentication = { attachPayload: true };
      break;
    case 'presentation.device-signature-other-key':
      holderPrivateKey = (await generateEcKeyPair()).privateKey;
      break;
    case 'presentation.device-signed-element':
      deviceNameSpaces = new Map([[PID_NAMESPACE, new Map<string, unknown>([['family_name', 'Musterfrau']])]]);
      break;
    case 'presentation.device-signature-es256k': {
      const key = keys.secp256k1;
      if (!key) throw new Error('presentation.device-signature-es256k needs the secp256k1 key the mdoc is bound to');
      deviceSigner = { alg: COSE_ALG.ES256K, sign: (data) => signEs256k(key, data) };
      break;
    }
    default:
      throw new Error(`fault ${fault} is not implemented for mdoc`);
  }
  const deviceResponse = await presentMdoc(issuerSigned, {
    holderPrivateKey,
    handover,
    nonce,
    jwkThumbprint: thumbprint,
    elements: requested.elements,
    deviceNameSpaces,
    deviceSigner,
    docType,
    deviceAuthentication,
  });
  if (fault === 'presentation.device-signature-bitflip' || fault === 'presentation.no-device-auth' || fault === 'presentation.device-signature-missing') {
    const response = decodeCbor<CborMap>(deviceResponse);
    const deviceSigned = ((response.get('documents') as CborMap[])[0]?.get('deviceSigned') ?? new Map()) as CborMap;
    if (fault === 'presentation.no-device-auth') {
      deviceSigned.delete('deviceAuth');
    } else if (fault === 'presentation.device-signature-missing') {
      deviceSigned.set('deviceAuth', new Map());
    } else {
      const deviceAuth = deviceSigned.get('deviceAuth') as CborMap;
      const signature = readCose(deviceAuth.get('deviceSignature'));
      deviceAuth.set('deviceSignature', coseValue({ ...signature, signature: flipBitInBytes(signature.signature) }));
    }
    return encodeDeviceResponse(encodeCbor(response));
  }
  return encodeDeviceResponse(deviceResponse);
}
