// A new version of a trust list that a step publishes (RP_WS_SM_TrustMechanisms_007, _008 and RP_Inf_SM_TrustMechanisms):
// the PID Provider LoTE `TL-PID`, or the Trusted List `TL-QEAA`, with the changes of the step and at most one trust-list
// fault. The harness and the self-validation build it with the same function. Issue 26: the issuer suite publishes
// versions of the Wallet Provider LoTE `TL-WP` the same way (PP_Inf_SM_TrustMechanisms), sealed by its own scheme operator.
import { faultInfo, type IssuerTrustListAction, type TrustListAction } from '@eudi-pcaf/core';
import { LOTE_TYPES } from '@owf/eudi-lote';
import { flipBitInSegment } from './jose';
import { buildLoteDocument, sealLote } from './lote';
import type { LoteListId, TestPki, TrustedListId } from './pki';
import { buildTrustedLists, TRUSTED_LIST_MEDIA_TYPE } from './trusted-list';

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;
const MONTH_MS = 30 * DAY_MS;

export interface TrustListVersionContext {
  pki: TestPki;
  /** The entities of the version, after the step's removals and additions. */
  entities: string[];
  /** The sequence number of the version, unless it rolls back. */
  sequenceNumber: number;
  /** The sequence number of the version the Relying Party retrieved before, for `trust-list.rollback`. */
  previousSequenceNumber: number;
  /** Where `TL-PID` is published, or where the LOTL and `TL-QEAA` are. */
  location?: string;
  locations?: Record<TrustedListId, string>;
  /** The grace period `G` of the Relying Party (ICS RP.T.2), milliseconds. */
  graceMs: number;
  now?: Date;
}

export interface TrustListVersion {
  body: string;
  contentType: string;
  sequenceNumber: number;
}

/** Builds the version of `TL-PID` or `TL-QEAA` a trust-list step publishes. */
export async function buildTrustListVersion(action: TrustListAction | IssuerTrustListAction, ctx: TrustListVersionContext): Promise<TrustListVersion> {
  const now = ctx.now ?? new Date();
  const [fault] = action.faults ?? [];
  if (fault) {
    const info = faultInfo(fault);
    const format = action.list === 'TL-QEAA' ? 'trusted-list' : 'lote';
    if (info.point !== 'trust-list' || info.format !== format) throw new Error(`fault ${fault} does not apply to ${action.list}`);
  }
  if (action.list === 'TL-QEAA') {
    if (!ctx.locations) throw new Error('TL-QEAA needs the locations of the LOTL and TL-QEAA');
    const lists = await buildTrustedLists({
      pki: ctx.pki,
      locations: ctx.locations,
      entities: ctx.entities,
      grantQualified: 'grantQualified' in action ? action.grantQualified : undefined,
      sequenceNumber: ctx.sequenceNumber,
      ...(fault === 'trusted-list.signer-ca-x' ? { qeaaSigner: ctx.pki.entities['CA-X'].signers.issuance } : {}),
      now,
    });
    return { body: lists['TL-QEAA'], contentType: TRUSTED_LIST_MEDIA_TYPE, sequenceNumber: ctx.sequenceNumber };
  }
  const rollback = fault === 'trust-list.rollback';
  const sequenceNumber = rollback ? ctx.previousSequenceNumber - 1 : ctx.sequenceNumber;
  if (sequenceNumber < 1) throw new Error('a rollback needs a version with a sequence number above 1 before it');
  const staleBy = fault === 'trust-list.stale-within-grace' ? ctx.graceMs / 2 : fault === 'trust-list.stale-after-grace' ? ctx.graceMs + HOUR_MS : undefined;
  const nextUpdate = staleBy === undefined ? undefined : new Date(now.getTime() - staleBy);
  const list: LoteListId = action.list === 'TL-WP' ? 'TL-WP' : 'TL-PID';
  const document = buildLoteDocument({
    list,
    pki: ctx.pki,
    entities: ctx.entities,
    sequenceNumber,
    distributionPoint: ctx.location,
    restoreIssuance: action.restoreIssuance,
    ...('withdraw' in action && action.withdraw ? { withdrawIssuance: action.withdraw } : {}),
    now,
    ...(nextUpdate ? { issued: new Date(nextUpdate.getTime() - MONTH_MS), nextUpdate } : {}),
    ...(rollback ? { issued: new Date(now.getTime() - DAY_MS) } : {}),
    ...(fault === 'trust-list.wrong-type' ? { loteType: LOTE_TYPES.EUWalletProvidersList } : {}),
  });
  const sealer = fault === 'trust-list.sealed-by-ca-x' ? ctx.pki.entities['CA-X'].signers.issuance : ctx.pki.schemeOperators[list];
  let jws = await sealLote(document, sealer, now);
  if (fault === 'trust-list.seal-bitflip') jws = flipBitInSegment(jws, 2);
  return { body: jws, contentType: 'application/jwt', sequenceNumber };
}
