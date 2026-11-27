// Combined presentations (RP_WS_UC_Presentation): the credentials of a step, each for its own credential query, and the
// `vp_token` that carries their presentations, valid or with one `vp-token` fault. The Conformance Wallet and the
// self-validation build the `vp_token` with the same function, so the self-validated `vp_token` is the one the Relying
// Party receives.
import { type DcqlQuery, type FaultId, faultInfo, type PresentationAction } from '@eudi-pcaf/core';
import { type CborMap, decodeCbor, decodeEmbedded, encodeCbor, type Tagged } from './cbor';
import { base64url } from './crypto';
import { encodeDeviceResponse, requestedElements } from './mdoc';
import type { HeldCredential, RequestedClaims } from './presentation';
import { type ForgedCredential, forgePresentation, type StepForgeContext } from './step';

export type CredentialQuery = DcqlQuery['credentials'][number];

/** The key of the extra `vp_token` entry of `vp-token.unknown-id`: the `id` of no credential query. */
export const UNKNOWN_QUERY_ID = 'x';

/**
 * The credential query a held credential answers: the one it names (`HeldCredential.query`), or the first of its format.
 */
export function credentialQueryOf(query: DcqlQuery, held: Pick<HeldCredential, 'format' | 'query'>): CredentialQuery {
  const found = held.query ? query.credentials.find((c) => c.id === held.query) : query.credentials.find((c) => c.format === held.format);
  if (!found) throw new Error(held.query ? `the request has no credential query ${held.query}` : `the request asks for no credential in ${held.format} format`);
  if (found.format !== held.format) throw new Error(`the credential query ${found.id} asks for ${found.format}, not ${held.format}`);
  return found;
}

/** What a credential query asks for: the top-level claims of an SD-JWT VC to disclose, the elements of an mdoc. */
export function requestedClaimsOf(credentialQuery: CredentialQuery): RequestedClaims {
  return {
    disclose: [...new Set((credentialQuery.claims ?? []).map((claim) => String(claim.path[0])))],
    elements: requestedElements(credentialQuery.claims),
    paths: (credentialQuery.claims ?? []).map((claim) => claim.path),
  };
}

/** Every claim a held credential can disclose: the names of its disclosures, or every element of every namespace. */
export function allClaimsOf(held: HeldCredential): RequestedClaims {
  if (held.format === 'mso_mdoc') {
    const issuerSigned = decodeCbor<CborMap>(held.value);
    const elements: Record<string, string[]> = {};
    for (const [namespace, items] of (issuerSigned.get('nameSpaces') as Map<string, Tagged[]>) ?? new Map()) {
      elements[namespace] = items.map((item) => String(decodeEmbedded<CborMap>(item).get('elementIdentifier')));
    }
    return { disclose: [], elements };
  }
  const names = held.value
    .split('~')
    .slice(1)
    .filter(Boolean)
    .map((disclosure) => {
      try {
        const elements = base64url.decodeJson<unknown[]>(disclosure);
        return elements.length === 3 ? String(elements[1]) : undefined;
      } catch {
        return undefined;
      }
    })
    .filter((name): name is string => Boolean(name));
  return { disclose: [...new Set(names)], elements: {} };
}

/**
 * One DeviceResponse with the documents of several DeviceResponses (`vp-token.combined-device-response`, against HAIP
 * 1.0 section 5.3.1). Each document keeps its own device signature, which covers its docType and the SessionTranscript,
 * not the DeviceResponse around it, so every document stays valid.
 */
export function mergeDeviceResponses(entries: string[]): string {
  const responses = entries.map((entry) => decodeCbor<CborMap>(base64url.decode(entry)));
  const documents = responses.flatMap((response) => (response.get('documents') as unknown[]) ?? []);
  return encodeDeviceResponse(encodeCbor(new Map<string, unknown>([['version', '1.0'], ['documents', documents], ['status', 0]])));
}

/** Builds the presentation of a held credential for what is requested; `primary` marks the step's own credential. */
export type PresentCredential = (held: HeldCredential, requested: RequestedClaims, primary: boolean) => Promise<string>;

export interface BuiltVpToken {
  vpToken: Record<string, string[]>;
  /** The presentation of the step's own credential (the first held credential), for evidence and replay. */
  presentation: string;
}

/**
 * Builds the `vp_token` for a request: one entry per held credential, under the `id` of the credential query it
 * answers, each with one presentation of what that query requests; then applies `fault`, a fault at the point
 * `vp-token`, to the entry of the first held credential.
 */
export async function buildVpToken(query: DcqlQuery, held: HeldCredential[], present: PresentCredential, fault?: FaultId): Promise<BuiltVpToken> {
  if (fault && faultInfo(fault).point !== 'vp-token') throw new Error(`fault ${fault} does not apply to the vp_token`);
  const [first] = held;
  if (!first) throw new Error('no credential to present');
  const vpToken: Record<string, string[]> = {};
  const ids: string[] = [];
  let presentation = '';
  for (const [index, credential] of held.entries()) {
    const credentialQuery = credentialQueryOf(query, credential);
    if (vpToken[credentialQuery.id]) throw new Error(`two credentials answer the credential query ${credentialQuery.id}`);
    const entry = await present(credential, requestedClaimsOf(credentialQuery), index === 0);
    if (index === 0) presentation = entry;
    vpToken[credentialQuery.id] = [entry];
    ids.push(credentialQuery.id);
  }
  const firstId = ids[0] as string;
  switch (fault) {
    case undefined:
      break;
    case 'vp-token.entry-missing':
      if (ids.length < 2) throw new Error('vp-token.entry-missing needs a second credential, or the vp_token would be empty');
      delete vpToken[firstId];
      break;
    case 'vp-token.unknown-id':
      if (query.credentials.some((c) => c.id === UNKNOWN_QUERY_ID)) throw new Error(`the request has a credential query ${UNKNOWN_QUERY_ID}`);
      vpToken[UNKNOWN_QUERY_ID] = [await present(first, allClaimsOf(first), false)];
      break;
    case 'vp-token.two-presentations': {
      if (credentialQueryOf(query, first).multiple) throw new Error('vp-token.two-presentations needs a credential query without multiple');
      (vpToken[firstId] as string[]).push(await present(first, requestedClaimsOf(credentialQueryOf(query, first)), false));
      break;
    }
    case 'vp-token.combined-device-response': {
      if (held.some((c) => c.format !== 'mso_mdoc') || ids.length < 2) throw new Error('vp-token.combined-device-response needs two mdocs');
      const merged = mergeDeviceResponses(ids.map((id) => (vpToken[id] as string[])[0] as string));
      for (const id of ids) vpToken[id] = [merged];
      break;
    }
    default:
      throw new Error(`fault ${fault} is not implemented for the vp_token`);
  }
  return { vpToken, presentation };
}

/** A credential of a step with the credential query it answers (left out for the step's own credential without `answers`). */
export interface ForgedStepCredential {
  answers?: string;
  forged: ForgedCredential;
}

/**
 * Forges every credential of a presentation step: the step's own credential (with its status list or identifier list
 * and its fault), then each credential presented alongside it (UC_Presentation), with its own status list.
 */
export async function forgePresentations(action: PresentationAction, ctx: StepForgeContext): Promise<ForgedStepCredential[]> {
  const forged: ForgedStepCredential[] = [{ ...(action.answers ? { answers: action.answers } : {}), forged: await forgePresentation(action, ctx) }];
  for (const other of action.alongside ?? []) {
    const otherAction: PresentationAction = {
      kind: 'presentation',
      query: action.query,
      credential: other.credential,
      statusList: other.statusList,
      identifierList: null,
      response: { faults: [] },
    };
    forged.push({ answers: other.answers, forged: await forgePresentation(otherAction, ctx) });
  }
  return forged;
}

/** The credential the Conformance Wallet holds for a forged credential. */
export function heldCredentialOf(credential: ForgedStepCredential): HeldCredential {
  const { forged, answers } = credential;
  return forged.format === 'mso_mdoc'
    ? { format: 'mso_mdoc', value: forged.credential as Uint8Array, ...(forged.documentDocType ? { docType: forged.documentDocType } : {}), ...(answers ? { query: answers } : {}) }
    : { format: 'dc+sd-jwt', value: forged.credential as string, ...(answers ? { query: answers } : {}) };
}
