// The security mechanisms of an issuance (issue 19: PP_WS_SM_ClientAttestation, _KeyAttestation, _ProofOfPossession):
// how the runner turns an issuance step into the Wallet Unit binding and the message hooks of the issuance client
// (one named issuer fault, the values a replay fault needs, the `attestation` proof type), how it executes a
// `wallet-event` step of the Test Wallet Provider, and the `maintenance-period` check of an issued credential.
//
// A `wallet-event` step does not change the shared `SL-WP-A`: the Test Wallet Provider serves the changed version for
// this test case under a URL of its own, and the Wallet Unit's WIA (or KA) of the following issuance steps of the test
// case refers to it, with the unit's index. A Provider may reuse a fetched list for its `ttl` (Token Status List
// section 13.7), so a change of the shared list could be masked by a copy fetched by an earlier test case, and would
// carry into every later one. The RP harness serves a status list per credential for the same reason.
import { type IssuanceAction, ISSUER_FAULTS, type IssuerFaultId, type WalletEventAction } from '@eudi-pcaf/core';
import { applyStatusListFault, buildStatusListTokenJwt, decodeJws } from '@eudi-pcaf/forge';
import {
  applyIssuerFault,
  type HttpExchange,
  type IssuanceEvidence,
  KEY_ATTESTATION_HEADER,
  type MessageHooks,
  type WalletUnitBinding,
} from '@eudi-pcaf/issuer-wallet';
import type { StatusProvider } from '@eudi-pcaf/status-provider';
import { CLIENT_ATTESTATION_HEADER, CLIENT_ATTESTATION_POP_HEADER, REVOKED, signerFor, type TestWalletProvider, type WalletUnitId } from '@eudi-pcaf/wallet-provider';

type StatusReference = { idx: number; uri: string };

/** What the steps of one test case share about the Wallet Units: moved status references and values for replays. */
export interface AttestationState {
  /** Status references a `wallet-event` step moved to a list of their own, per Wallet Unit. */
  status: Map<WalletUnitId, { wia?: StatusReference; ka?: StatusReference }>;
  /** The last `c_nonce` answered at the credential endpoint and the last PoP `jti` sent, per Wallet Unit. */
  last: Map<WalletUnitId, { cNonce?: string; popJti?: string }>;
  /** Issue 26: the entries of each list a wallet-event step served, so a later event of the test case changes it in place. */
  served?: Map<string, number[]>;
}

export const newAttestationState = (): AttestationState => ({ status: new Map(), last: new Map(), served: new Map() });

export const isIssuerRequestFault = (fault: string): fault is IssuerFaultId => Object.hasOwn(ISSUER_FAULTS, fault);

export interface PreparedIssuance {
  unit: WalletUnitBinding;
  hooks: MessageHooks;
  /** Turns the fault off (the hooks then send valid messages), for the retry with a fresh `c_nonce`. */
  withoutFault(): void;
}

const header = (headers: Record<string, string>, name: string) => Object.entries(headers).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1];

/**
 * The binding and hooks of an issuance step: the step's issuer fault (at most one) applied through the seams of the
 * issuance client, with the replay values of earlier steps of the same test case; the status references a
 * `wallet-event` step moved; the KA with the `c_nonce`, and the `attestation` proof type, if the step asks for them.
 */
export async function prepareIssuance(action: IssuanceAction, twp: TestWalletProvider, state: AttestationState): Promise<PreparedIssuance> {
  const [fault] = action.faults;
  if (fault !== undefined && !isIssuerRequestFault(fault)) throw new Error(`${fault} is not an issuer request fault`);
  const id = (action.walletUnit ?? 'CW-1') as WalletUnitId;
  const own = state.last.get(id);
  const other = [...state.last.entries()].find(([unit, values]) => unit !== id && values.cNonce)?.[1].cNonce;
  const attestation = action.proofType === 'attestation';
  const applied = await applyIssuerFault(fault, {
    twp,
    unit: id,
    replay: { ...(own?.cNonce ? { cNonce: own.cNonce } : {}), ...(own?.popJti ? { popJti: own.popJti } : {}) },
    ...(other ? { otherSessionCNonce: other } : {}),
    keyAttestationNonce: Boolean(action.keyAttestationNonce || attestation),
  });
  const moved = state.status.get(id);
  // Issue 26: a fault of the proof, DPoP or PoP leaves the moved WIA and KA as they are; one of the WIA or KA does not.
  if (moved && fault && ['wia', 'ka'].includes(ISSUER_FAULTS[fault].point)) throw new Error(`a step after a wallet-event applies no WIA or KA fault, not ${fault}`);
  const unit: WalletUnitBinding = {
    ...applied.unit,
    ...(moved?.wia ? { wia: () => twp.wia(id, { status: moved.wia! }) } : {}),
    ...(moved?.ka ? { keyAttestation: () => twp.keyAttestation(id, { status: moved.ka! }) } : {}),
  };
  // Without the fault the KA still carries the c_nonce where the step asks for it.
  const valid = fault ? await applyIssuerFault(undefined, { twp, unit: id, keyAttestationNonce: Boolean(action.keyAttestationNonce || attestation) }) : applied;
  let faulty = true;
  const hooks: MessageHooks = {
    jwt: (point, parts, context) => {
      const jwt = (faulty ? applied : valid).hooks.jwt;
      return jwt ? jwt(point, parts, context) : parts;
    },
    request: async (step, message) => {
      const changed = faulty && applied.hooks.request ? await applied.hooks.request(step, message) : message;
      return attestation && step === 'credential' ? asAttestationProof(changed) : changed;
    },
  };
  return {
    unit,
    hooks,
    withoutFault: () => {
      faulty = false;
    },
  };
}

/**
 * The `attestation` proof type (OpenID4VCI 1.0 Appendix F.3): the KA the client put into the `key_attestation` header
 * of its `jwt` proof, sent alone as `proofs.attestation`.
 */
export function asAttestationProof<M extends { body?: string }>(message: M): M {
  const body = JSON.parse(message.body ?? '{}') as { proofs?: { jwt?: string[]; attestation?: string[] } };
  const proof = body.proofs?.jwt?.[0];
  if (!proof) return message;
  const ka = decodeJws(proof).header[KEY_ATTESTATION_HEADER];
  body.proofs = typeof ka === 'string' ? { attestation: [ka] } : { attestation: [] };
  return { ...message, body: JSON.stringify(body) };
}

/**
 * Remembers what a later step of the test case may replay: the `jti` of a PoP the Provider accepted (token issued), and
 * the `c_nonce` of a credential request it answered with a credential. Values of refused requests are not kept, so a
 * replay always repeats a value the Provider has already accepted once.
 */
export function rememberIssuance(state: AttestationState, unit: WalletUnitId, evidence: IssuanceEvidence) {
  const values = { ...state.last.get(unit) };
  const pop = [...evidence.exchanges].reverse().find((e) => e.step === 'token' && e.response?.status === 200 && header(e.request.headers, CLIENT_ATTESTATION_POP_HEADER));
  if (pop) values.popJti = decodeJws(header(pop.request.headers, CLIENT_ATTESTATION_POP_HEADER)!).payload.jti as string;
  if (evidence.cNonce && evidence.credentials.length) values.cNonce = evidence.cNonce;
  state.last.set(unit, values);
}

export interface WalletEventContext {
  twp: TestWalletProvider;
  statusProvider: StatusProvider;
  /** Namespace of the status list URLs. */
  namespace: string;
  state: AttestationState;
  skewSeconds: number;
}

/**
 * A `wallet-event` step: the Test Wallet Provider revokes the unit's Wallet Instance (`revoke-instance`) or WSCD
 * (`revoke-wscd`), or serves its status list with one Status List Token fault of the RP harness or an HTTP status
 * (`status-list`), as a version of the provider's list under a URL of this test case. Returns what it served.
 */
export async function applyWalletEvent(action: WalletEventAction, ctx: WalletEventContext): Promise<string> {
  const { twp } = ctx;
  const id = (action.walletUnit ?? 'CW-1') as WalletUnitId;
  const unit = twp.units[id];
  const entity = twp.entityOf(unit.provider);
  const list = twp.statusLists[unit.provider];
  const of = action.event === 'revoke-wscd' ? 'ka' : action.event === 'revoke-instance' ? 'wia' : (action.statusList?.of ?? 'wia');
  const reference = of === 'wia' ? unit.wiaStatus : unit.kaStatus;
  // Issue 26: a list this test case already moved the attestation to is changed in place (revocation chaining: the
  // Provider must see the change at the URL the credential's WIA or KA referenced); otherwise a new URL of the test case.
  const moved = ctx.state.status.get(id)?.[of];
  const uri = moved?.uri ?? ctx.statusProvider.allocate(ctx.namespace);
  const statuses = [...(ctx.state.served?.get(uri) ?? list.statuses)];
  if (action.event !== 'status-list') statuses[reference.idx] = REVOKED;
  const now = new Date();
  const signer = signerFor(entity, 'status');
  const token = await buildStatusListTokenJwt({ signer, issuer: entity.issuerUri, uri, statuses, now });
  const [fault] = action.statusList?.faults ?? [];
  let served: string;
  if (action.event === 'status-list' && action.statusList?.httpStatus !== undefined) {
    ctx.statusProvider.register(uri, JSON.stringify({ error: 'unavailable' }), { status: action.statusList.httpStatus, contentType: 'application/json' });
    served = `HTTP ${action.statusList.httpStatus} without a token`;
  } else if (action.event === 'status-list' && fault) {
    const faulty = await applyStatusListFault(fault, token, {
      pki: twp.pki,
      issuer: unit.provider,
      signer,
      credentialSigner: signerFor(entity, of),
      uri,
      now,
      skewSeconds: ctx.skewSeconds,
    });
    ctx.statusProvider.register(uri, faulty.body, { contentType: faulty.contentType });
    served = `the token with fault ${fault}`;
  } else {
    ctx.statusProvider.register(uri, token);
    served = action.event === 'status-list' ? 'a valid token' : `a valid token with the ${of === 'wia' ? 'Wallet Instance' : 'WSCD'} entry ${reference.idx} revoked`;
  }
  ctx.state.served?.set(uri, statuses);
  ctx.state.status.set(id, { ...ctx.state.status.get(id), [of]: { idx: reference.idx, uri } });
  return `${list.id} of ${id}'s ${of === 'wia' ? 'WIA' : 'KA'} (entry ${reference.idx}) served at ${uri}: ${served}`;
}

/** The WIA and KA a credential request of the step carried (the last ones sent), as the Provider received them. */
export function sentAttestations(exchanges: HttpExchange[]): { wia?: string; ka?: string } {
  const token = [...exchanges].reverse().find((e) => e.step === 'token');
  const credential = [...exchanges].reverse().find((e) => e.step === 'credential');
  const wia = token ? header(token.request.headers, CLIENT_ATTESTATION_HEADER) : undefined;
  let ka: string | undefined;
  if (credential?.request.body) {
    const proofs = (JSON.parse(credential.request.body) as { proofs?: { jwt?: string[]; attestation?: string[] } }).proofs;
    ka = proofs?.attestation?.[0] ?? (proofs?.jwt?.[0] ? (decodeJws(proofs.jwt[0]).header[KEY_ATTESTATION_HEADER] as string | undefined) : undefined);
  }
  return { ...(wia ? { wia } : {}), ...(ka ? { ka } : {}) };
}

/**
 * `maintenance-period` (ISSU_12c, WUA_30): the credential's `exp` is no later than the end of the revocation maintenance
 * period of the WIA (`client_status.exp`) and of the KA (`key_storage_status.exp`) it was issued for.
 */
export function maintenancePeriodCheck(credential: string, sent: { wia?: string; ka?: string }) {
  const exp = decodeJws(credential.split('~')[0]).payload.exp;
  const ends = [
    ['WIA client_status.exp', sent.wia && (decodeJws(sent.wia).payload.client_status as { exp?: number } | undefined)?.exp],
    ['KA key_storage_status.exp', sent.ka && (decodeJws(sent.ka).payload.key_storage_status as { exp?: number } | undefined)?.exp],
  ].filter((entry): entry is [string, number] => typeof entry[1] === 'number');
  const iso = (t: number) => new Date(t * 1000).toISOString();
  if (typeof exp !== 'number') return { check: 'maintenance-period' as const, status: 'fail' as const, detail: 'the credential has no exp' };
  if (ends.length === 0) return { check: 'maintenance-period' as const, status: 'skip' as const, detail: 'neither WIA nor KA states a maintenance period' };
  const later = ends.filter(([, end]) => exp > end);
  return later.length
    ? { check: 'maintenance-period' as const, status: 'fail' as const, detail: `exp ${iso(exp)} is after ${later.map(([name, end]) => `${name} ${iso(end)}`).join(' and ')}` }
    : { check: 'maintenance-period' as const, status: 'pass' as const, detail: `exp ${iso(exp)} is no later than ${ends.map(([name, end]) => `${name} ${iso(end)}`).join(' and ')}` };
}
