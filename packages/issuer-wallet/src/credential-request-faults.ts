// The faults of the point `credential-request` (issuer harness design section 6.2; `CREDENTIAL_REQUEST_FAULTS` in
// @eudi-pcaf/core): each is a pure change of the JSON body of a valid credential request, applied by a request
// hook after the issuance client built the request and before it is sent. The values a fault needs (a second
// configuration of the metadata, the `credential_identifier` of the token response) come from the flow, so
// `issueWithCredentialRequestFault` runs `SCN-I` step by step and hands them to the hook.
import { randomBytes } from 'node:crypto';
import type { CredentialRequestFaultId } from '@eudi-pcaf/core';
import { IssuanceClient, type IssuanceClientOptions, type IssuanceEvidence, type IssueOptions, type WalletUnitBinding } from './client';
import type { RequestHook } from './http';

type Json = Record<string, unknown>;

/** What a credential request fault takes from the flow. */
export interface CredentialRequestFaultContext {
  /** The `credential_configuration_id` of the valid request. */
  configurationId: string;
  /** `credential_configurations_supported` of the metadata. */
  configurationIds: string[];
  /** The configurations the access token covers. */
  authorizedConfigurationIds: string[];
  /** The `credential_identifiers` the token response issued for the requested configuration. */
  credentialIdentifiers: string[];
  /** A `credential_identifier` of another session's token response (`identifier-foreign`). */
  foreignIdentifier?: string;
}

/** A fault that cannot be applied in this flow, for example without a second configuration in the metadata. */
export class CredentialRequestFaultNotApplicable extends Error {}

/**
 * Applies a fault to the JSON body of a valid credential request; returns a changed copy. Throws
 * `CredentialRequestFaultNotApplicable` when the flow lacks what the fault needs.
 */
export function applyCredentialRequestFault(id: CredentialRequestFaultId, body: Json, context: CredentialRequestFaultContext): Json {
  const copy: Json = structuredClone(body);
  switch (id) {
    case 'credential-request.configuration-unknown':
      copy.credential_configuration_id = `unknown-${randomBytes(8).toString('hex')}`;
      return copy;
    case 'credential-request.configuration-not-authorized': {
      const other = context.configurationIds.find((c) => !context.authorizedConfigurationIds.includes(c));
      if (!other) {
        throw new CredentialRequestFaultNotApplicable(`the metadata offers no configuration beyond ${context.authorizedConfigurationIds.join(', ')}, which the access token covers`);
      }
      copy.credential_configuration_id = other;
      return copy;
    }
    case 'credential-request.both-identifiers': {
      const [identifier] = context.credentialIdentifiers;
      if (!identifier) throw new CredentialRequestFaultNotApplicable(`the token response issued no credential_identifiers for ${context.configurationId}`);
      copy.credential_identifier = identifier;
      return copy;
    }
    case 'credential-request.no-identifier':
      delete copy.credential_configuration_id;
      delete copy.credential_identifier;
      return copy;
    case 'credential-request.identifier-foreign':
      if (!context.foreignIdentifier) throw new CredentialRequestFaultNotApplicable('no credential_identifier of another session');
      if (context.credentialIdentifiers.includes(context.foreignIdentifier)) {
        throw new CredentialRequestFaultNotApplicable(`the other session's credential_identifier ${context.foreignIdentifier} is also one of this token response`);
      }
      delete copy.credential_configuration_id;
      copy.credential_identifier = context.foreignIdentifier;
      return copy;
    case 'credential-request.extra-member':
      copy.foo = 'bar';
      return copy;
  }
}

/** A request hook that applies the fault to the credential request; `context` is read when the request is built. */
export function credentialRequestFaultHook(id: CredentialRequestFaultId, context: () => CredentialRequestFaultContext): RequestHook {
  return (step, request) => {
    if (step !== 'credential' || !request.body) return request;
    return { ...request, body: JSON.stringify(applyCredentialRequestFault(id, JSON.parse(request.body) as Json, context())) };
  };
}

export interface FaultyIssueOptions extends IssueOptions {
  fault: CredentialRequestFaultId;
  foreignIdentifier?: string;
}

/**
 * Runs `SCN-I` with one credential request fault: offer, metadata, token and nonce valid, then the credential request
 * with the fault. Never throws for the flow; `notApplicable` says why the fault could not be applied (nothing faulty was
 * sent then). The client is one of its own, with the fault's hook.
 */
export async function issueWithCredentialRequestFault(
  unit: WalletUnitBinding,
  options: FaultyIssueOptions,
  clientOptions: Omit<IssuanceClientOptions, 'hooks'> = {},
): Promise<{ evidence: IssuanceEvidence; notApplicable?: string; context?: CredentialRequestFaultContext }> {
  let context: CredentialRequestFaultContext | undefined;
  const client = await IssuanceClient.create(unit, {
    ...clientOptions,
    hooks: { request: credentialRequestFaultHook(options.fault, () => context as CredentialRequestFaultContext) },
  });
  const evidence: IssuanceEvidence = { walletUnit: unit.id, exchanges: [], credentials: [] };
  try {
    const offer = await client.resolveOffer(options.offer, evidence);
    const metadata = await client.fetchMetadata(offer.offer.credential_issuer, evidence, { signed: options.signedMetadata ?? false });
    // Issue 20: in the authorization code flow, PAR and the authorization request through the adapter first.
    const token =
      options.grant === 'authorization_code'
        ? await (async () => {
            if (!options.authenticate) throw new Error('the authorization code flow needs the adapter to authenticate the subject (authenticateSubject)');
            const configuration = options.credentialConfigurationId ?? offer.offer.credential_configuration_ids[0];
            const authorization = await client.authorize(offer.offer, metadata.result, configuration, evidence, { authenticate: options.authenticate });
            return client.requestAuthorizationCodeToken(metadata.result, authorization, evidence);
          })()
        : await client.requestToken(offer.offer, metadata.result, evidence, options.txCode);
    const cNonce = await client.requestNonce(metadata.result, evidence);
    const configurationId = options.credentialConfigurationId ?? offer.offer.credential_configuration_ids[0];
    const details = (Array.isArray(token.response.authorization_details) ? token.response.authorization_details : []) as Json[];
    const covered = details.map((d) => d.credential_configuration_id).filter((c): c is string => typeof c === 'string');
    context = {
      configurationId,
      configurationIds: Object.keys(metadata.result.credentialIssuer.credential_configurations_supported),
      authorizedConfigurationIds: covered.length ? covered : offer.offer.credential_configuration_ids,
      credentialIdentifiers: details
        .filter((d) => d.credential_configuration_id === configurationId)
        .flatMap((d) => (Array.isArray(d.credential_identifiers) ? d.credential_identifiers : []))
        .filter((c): c is string => typeof c === 'string'),
      ...(options.foreignIdentifier !== undefined ? { foreignIdentifier: options.foreignIdentifier } : {}),
    };
    // The hook throws before anything is sent when the fault cannot be applied.
    applyCredentialRequestFault(options.fault, { credential_configuration_id: configurationId }, context);
    await client.requestCredential(metadata.result, token, configurationId, cNonce, evidence);
  } catch (error) {
    if (error instanceof CredentialRequestFaultNotApplicable) return { evidence, notApplicable: error.message, ...(context ? { context } : {}) };
    evidence.error = (error as Error).message;
  }
  return { evidence, ...(context ? { context } : {}) };
}
