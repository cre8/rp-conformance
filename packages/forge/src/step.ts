// Builds the artifacts of a presentation step: the Status List Token or identifier list the Test Status Provider serves
// and the credential the Conformance Wallet presents, valid first and then with the step's fault. The controller and
// the self-validation use the same function, so the self-validated artifacts are the ones the Relying Party receives.
import { randomInt } from 'node:crypto';
import type { CredentialFormat, PresentationAction } from '@rp-conformance/core';
import { applyCredentialFault, applyStatusListFault, type ServedStatusList, type StatusListFaultContext } from './faults';
import { applyIdentifierListFault, applyMdocFault, applyStatusListCwtFault } from './faults-cose';
import { buildIdentifierListCwt, IDENTIFIER_LIST_CWT_TYPE } from './identifier-list';
import { issueCredentialAMdoc, issueCredentialASdJwtVc } from './attestation';
import { issuePidMdoc, newMdocIdentifier } from './mdoc';
import { issuePidSdJwtVc } from './pid';
import { type CertifiedKey, createDocumentSigner, documentSignerValidity, type TestEntity, type TestPki } from './pki';
import { buildStatusListTokenCwt, buildStatusListTokenJwt, STATUS_LIST_CWT_TYPE } from './status-list';

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
  /** The token before the fault: a compact JWT, or a CWT. */
  validToken: string | Uint8Array;
  /** What the Test Status Provider serves. */
  served: ServedStatusList;
}

export interface ForgedIdentifierList {
  uri: string;
  /** The MSO identifier of the credential. */
  identifier: Uint8Array;
  contains: boolean;
  validToken: Uint8Array;
  served: ServedStatusList;
}

export interface ForgedCredential {
  format: CredentialFormat;
  /** What the Conformance Wallet presents: the SD-JWT VC (without KB-JWT), or the mdoc's `IssuerSigned` (CBOR). */
  credential: string | Uint8Array;
  /** The issued claims, for comparing released attributes: top-level claims, or attributes by namespace for an mdoc. */
  claims: Record<string, unknown>;
  signer: CertifiedKey;
  statusList?: ForgedStatusList;
  identifierList?: ForgedIdentifierList;
}

const bitsFor = (values: number[]): 1 | 2 | 4 | 8 => {
  const max = Math.max(...values);
  return max <= 1 ? 1 : max <= 3 ? 2 : max <= 15 ? 4 : 8;
};

/** The certificate that signs credentials of `format` for an entity: its SD-JWT VC signer, or its mdoc document signer. */
export const credentialSignerOf = (entity: TestEntity, format: CredentialFormat): CertifiedKey =>
  format === 'mso_mdoc' ? entity.signers.mdoc : entity.signers.issuance;

/** Forges the credential and its status list or identifier list of a presentation step, with the step's fault applied. */
export async function forgePresentation(action: PresentationAction, ctx: StepForgeContext): Promise<ForgedCredential> {
  const now = ctx.now ?? new Date();
  const spec = action.credential;
  const issuer = ctx.pki.entities[spec.issuer];
  if (!issuer) throw new Error(`no entity ${spec.issuer} in the test PKI`);
  const signer = await signerOf(issuer, spec.format, spec.signedUnder, now);
  const faultContext = (listSigner: CertifiedKey, uri: string): StatusListFaultContext => ({
    pki: ctx.pki,
    issuer: spec.issuer,
    signer: listSigner,
    credentialSigner: signer,
    uri,
    now,
    skewSeconds: ctx.skewSeconds,
  });

  let statusList: ForgedStatusList | undefined;
  if (action.statusList) {
    const listSpec = action.statusList;
    const others = listSpec.others ?? 0;
    const bits = listSpec.bits ?? bitsFor([listSpec.status, others]);
    const index = listSpec.index ?? randomInt(0, STATUS_LIST_ENTRIES);
    const statuses = new Array<number>(STATUS_LIST_ENTRIES).fill(others);
    statuses[index] = listSpec.status;
    const signerEntity = ctx.pki.entities[listSpec.signer?.entity ?? spec.issuer];
    const listSigner = listSpec.signer?.key === 'issuance' ? credentialSignerOf(signerEntity, spec.format) : signerEntity.signers.revocation;
    const uri = ctx.allocateStatusUri();
    const options = { signer: listSigner, issuer: signerEntity.issuerUri, uri, statuses, bits, now };
    const [fault] = listSpec.faults;
    let validToken: string | Uint8Array;
    let served: ServedStatusList;
    if (listSpec.format === 'cwt') {
      const token = await buildStatusListTokenCwt(options);
      validToken = token;
      served = fault ? await applyStatusListCwtFault(fault, token, faultContext(listSigner, uri)) : { body: token, contentType: STATUS_LIST_CWT_TYPE };
    } else {
      const token = await buildStatusListTokenJwt(options);
      validToken = token;
      served = fault ? await applyStatusListFault(fault, token, faultContext(listSigner, uri)) : { body: token, contentType: 'application/statuslist+jwt' };
    }
    statusList = { uri, index, entries: STATUS_LIST_ENTRIES, bits, validToken, served };
  }

  let identifierList: ForgedIdentifierList | undefined;
  if (action.identifierList) {
    const listSpec = action.identifierList;
    const uri = ctx.allocateStatusUri();
    const identifier = newMdocIdentifier();
    const listSigner = issuer.signers.revocation;
    // Other revoked identifiers, so the list is never empty and the credential's own is one entry of several.
    const identifiers = [newMdocIdentifier(), ...(listSpec.contains ? [identifier] : []), newMdocIdentifier()];
    const token = await buildIdentifierListCwt({ signer: listSigner, issuer: issuer.issuerUri, uri, identifiers, now });
    const [fault] = listSpec.faults;
    const served = fault ? await applyIdentifierListFault(fault, token, faultContext(listSigner, uri)) : { body: token, contentType: IDENTIFIER_LIST_CWT_TYPE };
    identifierList = { uri, identifier, contains: listSpec.contains, validToken: token, served };
  }

  const short = spec.defaultCredential === 'default_credential_pid_short';
  // `default_credential_qeaa`, `_pubeaa` and `_eaa` are `default_credential_A`, issued like the PID.
  const pid = spec.defaultCredential === 'default_credential_pid' || short;
  const [fault] = spec.faults;
  if (spec.format === 'mso_mdoc') {
    const issued = await (pid ? issuePidMdoc : issueCredentialAMdoc)({
      signer,
      holderPublicJwk: ctx.holderPublicJwk,
      status:
        statusList || identifierList
          ? {
              ...(statusList ? { statusList: { uri: statusList.uri, idx: statusList.index } } : {}),
              ...(identifierList ? { identifierList: { uri: identifierList.uri, id: identifierList.identifier } } : {}),
            }
          : undefined,
      now,
      short,
    });
    const credential = fault
      ? await applyMdocFault(fault, issued.issuerSigned, { signer, now, skewSeconds: ctx.skewSeconds, statusListEntries: statusList?.entries })
      : issued.issuerSigned;
    return { format: spec.format, credential, claims: issued.claims, signer, statusList, identifierList };
  }

  const issued = await (pid ? issuePidSdJwtVc : issueCredentialASdJwtVc)({
    signer,
    issuer: issuer.issuerUri,
    holderPublicJwk: ctx.holderPublicJwk,
    status: statusList && { uri: statusList.uri, idx: statusList.index },
    now,
    ...(short ? { validitySeconds: SHORT_VALIDITY_SECONDS } : {}),
  });
  const credential = fault
    ? await applyCredentialFault(fault, issued.compact, { signer, now, skewSeconds: ctx.skewSeconds, statusListEntries: statusList?.entries })
    : issued.compact;
  return { format: spec.format, credential, claims: issued.claims, signer, statusList, identifierList };
}

/**
 * The certificate a credential is signed with. Under the revocation anchor (TrustMechanisms_004) an SD-JWT VC uses the
 * status list signer of the entity; an mdoc a document signer issued under that anchor, so the anchor is the only
 * difference from a valid mdoc.
 */
async function signerOf(issuer: TestEntity, format: CredentialFormat, signedUnder: 'issuance' | 'revocation' | undefined, now: Date) {
  if (signedUnder !== 'revocation') return credentialSignerOf(issuer, format);
  if (format !== 'mso_mdoc') return issuer.signers.revocation;
  return createDocumentSigner(issuer.anchors.revocation, issuer.spec.id, `${issuer.spec.id} document signer under the revocation anchor`, documentSignerValidity(now), issuer.issuerUri);
}
