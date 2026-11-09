// Builds the artifacts of a presentation step: the Status List Token the Test Status Provider serves and the credential
// the Conformance Wallet presents, valid first and then with the step's fault. The controller and the self-validation
// use the same function, so the self-validated artifacts are the ones the Relying Party receives.
import { randomInt } from 'node:crypto';
import type { PresentationAction } from '@rp-conformance/core';
import { applyCredentialFault, applyStatusListFault, type ServedStatusList } from './faults';
import { issuePidSdJwtVc } from './pid';
import type { CertifiedKey, TestPki } from './pki';
import { buildStatusListTokenJwt } from './status-list';

/** Entries of every status list the harness issues; 1024 entries are 128 bytes at one bit per status. */
export const STATUS_LIST_ENTRIES = 1024;
/** Validity of `default_credential_pid_short`: less than 24 hours. */
export const SHORT_VALIDITY_SECONDS = 12 * 60 * 60;

export interface StepForgeContext {
  pki: TestPki;
  /** The Conformance Wallet key the credential is bound to. */
  holderPublicJwk: JsonWebKey;
  /** A new, unique status list URI (harness design section 4.6). */
  allocateStatusUri: () => string;
  /** `T_skew`, seconds, for time faults. */
  skewSeconds: number;
  now?: Date;
}

export interface ForgedStatusList {
  uri: string;
  index: number;
  entries: number;
  bits: number;
  /** The token before the fault. */
  validToken: string;
  /** What the Test Status Provider serves. */
  served: ServedStatusList;
}

export interface ForgedCredential {
  /** The SD-JWT VC (without KB-JWT) the Conformance Wallet presents. */
  compact: string;
  /** The issued claims, for comparing released attributes. */
  claims: Record<string, unknown>;
  signer: CertifiedKey;
  statusList?: ForgedStatusList;
}

const bitsFor = (values: number[]): 1 | 2 | 4 | 8 => {
  const max = Math.max(...values);
  return max <= 1 ? 1 : max <= 3 ? 2 : max <= 15 ? 4 : 8;
};

/** Forges the credential and Status List Token of a presentation step, with the step's fault applied. */
export async function forgePresentation(action: PresentationAction, ctx: StepForgeContext): Promise<ForgedCredential> {
  const now = ctx.now ?? new Date();
  const spec = action.credential;
  const issuer = ctx.pki.entities[spec.issuer];
  if (!issuer) throw new Error(`no entity ${spec.issuer} in the test PKI`);
  const signer = spec.signedUnder === 'revocation' ? issuer.signers.revocation : issuer.signers.issuance;

  let statusList: ForgedStatusList | undefined;
  if (action.statusList) {
    const listSpec = action.statusList;
    const others = listSpec.others ?? 0;
    const bits = listSpec.bits ?? bitsFor([listSpec.status, others]);
    const index = listSpec.index ?? randomInt(0, STATUS_LIST_ENTRIES);
    const statuses = new Array<number>(STATUS_LIST_ENTRIES).fill(others);
    statuses[index] = listSpec.status;
    const signerEntity = ctx.pki.entities[listSpec.signer?.entity ?? spec.issuer];
    const listSigner = listSpec.signer?.key === 'issuance' ? signerEntity.signers.issuance : signerEntity.signers.revocation;
    const uri = ctx.allocateStatusUri();
    const validToken = await buildStatusListTokenJwt({ signer: listSigner, issuer: signerEntity.issuerUri, uri, statuses, bits, now });
    const [fault] = listSpec.faults;
    const served = fault
      ? await applyStatusListFault(fault, validToken, {
          pki: ctx.pki,
          issuer: spec.issuer,
          signer: listSigner,
          credentialSigner: signer,
          uri,
          now,
          skewSeconds: ctx.skewSeconds,
        })
      : { body: validToken, contentType: 'application/statuslist+jwt' };
    statusList = { uri, index, entries: STATUS_LIST_ENTRIES, bits, validToken, served };
  }

  const issued = await issuePidSdJwtVc({
    signer,
    issuer: issuer.issuerUri,
    holderPublicJwk: ctx.holderPublicJwk,
    status: statusList && { uri: statusList.uri, idx: statusList.index },
    now,
    ...(spec.defaultCredential === 'default_credential_pid_short' ? { validitySeconds: SHORT_VALIDITY_SECONDS } : {}),
  });
  const [fault] = spec.faults;
  const compact = fault
    ? await applyCredentialFault(fault, issued.compact, { signer, now, skewSeconds: ctx.skewSeconds, statusListEntries: statusList?.entries })
    : issued.compact;
  return { compact, claims: issued.claims, signer, statusList };
}
