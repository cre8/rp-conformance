// The identifier list procedure of the reference validator (ISO/IEC 18013-5 second edition section 12.3.6.4): the
// checks of a Status List Token in CWT format, which section 12.3.6.1 makes binding on both revocation mechanisms, and
// absence of the MSO's identifier.
import { type CborMap, COSE, COSE_ALG } from '@rp-conformance/forge';
import { type CheckRecorder, NotApplicable } from './checks';
import { CWT, decodeCoseToken, type FetchedStatusList, fail, leafJwk, verifyCoseSign1 } from './status-list';
import type { MatchedIssuer } from './trust';
import { validatePath } from './x509-path';

export const IDENTIFIER_LIST_TYPE = 'application/identifierlist+cwt';

export interface IdentifierListInput {
  /** The MSO's `identifier_list` entry. */
  reference: { uri: string; id: Uint8Array } | undefined;
  /** The trusted issuer the credential matched, with the anchors its identifier lists must be signed under. */
  issuer: MatchedIssuer | undefined;
  fetchIdentifierList: (uri: string) => Promise<FetchedStatusList>;
  skewSeconds: number;
  now: Date;
  /** Called right before the identifier list is requested. */
  onFetched?: () => void;
}

const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((byte, i) => byte === b[i]);

/** Runs the identifier list checks for the MSO's `identifier_list` entry; without one they are skipped. */
export async function evaluateIdentifierList(recorder: CheckRecorder, input: IdentifierListInput): Promise<void> {
  const { reference, now } = input;
  const nowSeconds = Math.floor(now.getTime() / 1000);
  let body: Uint8Array = new Uint8Array();
  let token: ReturnType<typeof decodeCoseToken> | undefined;
  let identifiers: Map<unknown, unknown> | undefined;

  await recorder.run('identifier-list-fetch', ['status-reference'], async () => {
    if (!reference) return new NotApplicable('the MSO has no identifier_list entry');
    input.onFetched?.();
    const response = await input.fetchIdentifierList(reference.uri);
    if (response.status !== 200) fail(`HTTP ${response.status}`);
    body = typeof response.body === 'string' ? new TextEncoder().encode(response.body) : response.body;
  });

  await recorder.run('identifier-list-format', ['identifier-list-fetch'], () => {
    token = decodeCoseToken(body);
  });

  await recorder.run('identifier-list-type', ['identifier-list-format'], () => {
    const typ = token?.structure.protectedHeader.get(COSE.typ);
    if (typ !== IDENTIFIER_LIST_TYPE) fail(`typ is ${String(typ)}, expected ${IDENTIFIER_LIST_TYPE}`);
  });

  await recorder.run('identifier-list-trust', ['identifier-list-format', 'issuer-trust'], async () => {
    if (!token?.chain?.length) fail('the identifier list has no x5chain in its protected header');
    const path = await validatePath(token?.chain ?? [], input.issuer?.statusAnchors ?? [], now);
    if (!path.ok) fail(`not under a revocation anchor of ${input.issuer?.name}: ${path.reason}`);
    return path.ok ? `${path.leaf.subject.commonName} under ${path.anchor.subject.commonName}` : undefined;
  });

  await recorder.run('identifier-list-signature', ['identifier-list-format'], async () => {
    const alg = token?.structure.protectedHeader.get(COSE.alg);
    if (alg !== COSE_ALG.ES256) fail(`alg ${String(alg)} is not accepted`);
    if (!token?.chain?.length) return new NotApplicable('no signer certificate, so no key to verify with');
    const jwk = leafJwk(token.chain);
    if (!jwk || jwk.crv !== 'P-256') fail('the signing certificate has no P-256 key');
    if (!(await verifyCoseSign1(token.structure, jwk as JsonWebKey))) fail('the identifier list signature does not verify');
  });

  await recorder.run('identifier-list-claims', ['identifier-list-format'], () => {
    const claims = token?.claims as CborMap;
    const list = claims.get(CWT.identifierList);
    const missing = [
      typeof claims.get(CWT.sub) !== 'string' && 'sub',
      typeof claims.get(CWT.iat) !== 'number' && 'iat',
      // Section 12.3.6.3: "The exp claim shall be present."
      typeof claims.get(CWT.exp) !== 'number' && 'exp',
      !(list instanceof Map) && 'identifier_list',
    ].filter(Boolean);
    if (missing.length) fail(`missing ${missing.join(', ')}`);
    const entries = (list as CborMap).get('identifiers');
    if (!(entries instanceof Map)) fail('identifier_list has no identifiers map');
    identifiers = entries as Map<unknown, unknown>;
    return `${identifiers.size} identifiers`;
  });

  await recorder.run('identifier-list-subject', ['identifier-list-format'], () => {
    const sub = token?.claims.get(CWT.sub);
    if (sub === undefined) return new NotApplicable('no sub');
    if (sub !== reference?.uri) fail(`sub ${String(sub)} is not the uri of the MSO's identifier_list entry`);
  });

  await recorder.run('identifier-list-validity', ['identifier-list-format'], () => {
    const exp = token?.claims.get(CWT.exp);
    if (exp === undefined) return new NotApplicable('no exp');
    if (typeof exp !== 'number') fail('exp is not a number');
    if (nowSeconds > (exp as number) + input.skewSeconds) fail(`expired: exp ${exp}, now ${nowSeconds}, T_skew ${input.skewSeconds}`);
  });

  await recorder.run('identifier-status', ['identifier-list-claims', 'status-reference'], () => {
    const id = reference?.id as Uint8Array;
    const listed = [...(identifiers?.keys() ?? [])].some((key) => key instanceof Uint8Array && sameBytes(key, id));
    if (listed) fail(`the MSO identifier ${Buffer.from(id).toString('hex')} is on the identifier list (revoked)`);
    return 'the MSO identifier is not listed';
  });
}
