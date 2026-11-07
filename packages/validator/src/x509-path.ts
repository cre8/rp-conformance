import { verifyEs256 } from '@rp-conformance/forge';
import { type Certificate, namesEqual, parseCertificate, verifyCertificateSignature } from '@owf/x509';

export type PathResult =
  | { ok: true; anchor: Certificate; leaf: Certificate }
  | { ok: false; reason: string };

const verifier = async ({ data, signatureP1363, publicKey }: { data: Uint8Array; signatureP1363: Uint8Array; publicKey: { jwk?: JsonWebKey } }) => {
  if (!publicKey.jwk || publicKey.jwk.kty !== 'EC' || publicKey.jwk.crv !== 'P-256') return false;
  return verifyEs256(publicKey.jwk, data, signatureP1363);
};

const sameCertificate = (a: Certificate, b: Certificate) => Buffer.from(a.der).equals(Buffer.from(b.der));

function withinValidity(certificate: Certificate, now: Date): string | undefined {
  if (now < certificate.notBefore) return `certificate ${certificate.subject.rfc4514} is not yet valid`;
  if (now > certificate.notAfter) return `certificate ${certificate.subject.rfc4514} has expired`;
  return undefined;
}

/**
 * Validates a certification path from the `x5c` chain (leaf first, base64 DER) to one of the given trust anchors
 * (RFC 5280 clause 6, reduced to what the test PKI uses): signatures, issuer names, validity of every certificate
 * including the anchor, `cA` for issuing certificates, and `digitalSignature` for the leaf. A copy of the anchor at
 * the end of `x5c` is ignored.
 */
export async function validatePath(x5c: string[], anchors: Certificate[], now = new Date()): Promise<PathResult> {
  if (x5c.length === 0) return { ok: false, reason: 'x5c is empty' };
  let chain: Certificate[];
  try {
    chain = x5c.map((entry) => parseCertificate(entry));
  } catch (error) {
    return { ok: false, reason: `x5c cannot be parsed: ${(error as Error).message}` };
  }
  while (chain.length > 1 && anchors.some((anchor) => sameCertificate(anchor, chain[chain.length - 1]))) chain = chain.slice(0, -1);
  const leaf = chain[0];
  if (leaf.basicConstraints?.cA) return { ok: false, reason: 'the signing certificate is a CA certificate' };
  if (leaf.keyUsage && !leaf.keyUsage.includes('digitalSignature')) {
    return { ok: false, reason: 'the signing certificate does not allow digitalSignature' };
  }
  for (const certificate of chain) {
    const problem = withinValidity(certificate, now);
    if (problem) return { ok: false, reason: problem };
  }
  for (let i = 0; i < chain.length - 1; i++) {
    const issuer = chain[i + 1];
    if (!issuer.basicConstraints?.cA) return { ok: false, reason: `${issuer.subject.rfc4514} is not a CA certificate` };
    if (!(await verifyCertificateSignature(chain[i], issuer.der, verifier))) {
      return { ok: false, reason: `signature of ${chain[i].subject.rfc4514} does not verify with ${issuer.subject.rfc4514}` };
    }
  }
  const top = chain[chain.length - 1];
  const candidates = anchors.filter((anchor) => namesEqual(anchor.subject, top.issuer));
  if (candidates.length === 0) return { ok: false, reason: `no trust anchor named ${top.issuer.rfc4514}` };
  for (const anchor of candidates) {
    if (!(await verifyCertificateSignature(top, anchor.der, verifier))) continue;
    const problem = withinValidity(anchor, now);
    if (problem) return { ok: false, reason: `trust anchor: ${problem}` };
    if (!anchor.basicConstraints?.cA) return { ok: false, reason: 'trust anchor is not a CA certificate' };
    return { ok: true, anchor, leaf };
  }
  return { ok: false, reason: `no trust anchor named ${top.issuer.rfc4514} verifies the chain` };
}
