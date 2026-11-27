// The requests the issuance client sends to the token, nonce and credential endpoints, each built by its own pure
// function from the values of the flow, so a fault can replace one member or the whole request.
import { CLIENT_ATTESTATION_HEADER, CLIENT_ATTESTATION_POP_HEADER } from '@eudi-pcaf/wallet-provider';
import type { HttpRequestMessage } from './http';

/** OpenID4VCI 1.0 section 4.1.1. */
export const PRE_AUTHORIZED_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

export interface TokenRequestInput {
  tokenEndpoint: string;
  preAuthorizedCode: string;
  txCode?: string;
  /** `client_id`; the WIA's `sub`. Left out when undefined. */
  clientId?: string;
  /** The WIA (`OAuth-Client-Attestation`). */
  clientAttestation?: string;
  /** Its proof of possession (`OAuth-Client-Attestation-PoP`). */
  clientAttestationPop?: string;
  /** The DPoP proof (`DPoP`). */
  dpop?: string;
}

/** Token request of the pre-authorized code flow (OpenID4VCI 1.0 section 6.1), form-encoded. */
export function tokenRequest(input: TokenRequestInput): HttpRequestMessage {
  const form = new URLSearchParams({ grant_type: PRE_AUTHORIZED_CODE_GRANT, 'pre-authorized_code': input.preAuthorizedCode });
  if (input.txCode !== undefined) form.set('tx_code', input.txCode);
  if (input.clientId !== undefined) form.set('client_id', input.clientId);
  return {
    method: 'POST',
    url: input.tokenEndpoint,
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
      ...(input.clientAttestation !== undefined ? { [CLIENT_ATTESTATION_HEADER]: input.clientAttestation } : {}),
      ...(input.clientAttestationPop !== undefined ? { [CLIENT_ATTESTATION_POP_HEADER]: input.clientAttestationPop } : {}),
      ...(input.dpop !== undefined ? { DPoP: input.dpop } : {}),
    },
    body: form.toString(),
  };
}

/** RFC 6749 section 4.1.3. */
export const AUTHORIZATION_CODE_GRANT = 'authorization_code';

/** Client authentication and DPoP of a request to the Authorization Server (PAR and token endpoint). */
export interface ClientHeaders {
  /** The WIA (`OAuth-Client-Attestation`). */
  clientAttestation?: string;
  /** Its proof of possession (`OAuth-Client-Attestation-PoP`). */
  clientAttestationPop?: string;
  /** The DPoP proof (`DPoP`). */
  dpop?: string;
}

const clientHeaders = (input: ClientHeaders) => ({
  ...(input.clientAttestation !== undefined ? { [CLIENT_ATTESTATION_HEADER]: input.clientAttestation } : {}),
  ...(input.clientAttestationPop !== undefined ? { [CLIENT_ATTESTATION_POP_HEADER]: input.clientAttestationPop } : {}),
  ...(input.dpop !== undefined ? { DPoP: input.dpop } : {}),
});

/** A form POST to the Authorization Server; parameters whose value is undefined are left out. */
function formPost(url: string, params: Record<string, string | undefined>, headers: ClientHeaders): HttpRequestMessage {
  const form = new URLSearchParams();
  for (const [name, value] of Object.entries(params)) if (value !== undefined) form.set(name, value);
  return {
    method: 'POST',
    url,
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json', ...clientHeaders(headers) },
    body: form.toString(),
  };
}

/**
 * The parameters of an authorization request of the authorization code flow (RFC 6749 section 4.1.1, RFC 7636 section
 * 4.3, OpenID4VCI 1.0 section 5.1): what the wallet pushes with PAR, or sends in the query without PAR.
 */
export type AuthorizationParameters = Record<string, string | undefined>;

/** Pushed authorization request (RFC 9126 section 2.1) with client attestation and DPoP (HAIP section 4.3). */
export function parRequest(endpoint: string, params: AuthorizationParameters, headers: ClientHeaders): HttpRequestMessage {
  return formPost(endpoint, params, headers);
}

/** The URL of an authorization request: the authorization endpoint with the parameters in its query. */
export function authorizationRequestUrl(endpoint: string, params: AuthorizationParameters): string {
  const url = new URL(endpoint);
  for (const [name, value] of Object.entries(params)) if (value !== undefined) url.searchParams.set(name, value);
  return url.toString();
}

export interface AuthorizationCodeTokenInput extends ClientHeaders {
  tokenEndpoint: string;
  code: string;
  codeVerifier?: string;
  redirectUri?: string;
  clientId?: string;
}

/** Token request of the authorization code flow (RFC 6749 section 4.1.3, RFC 7636 section 4.5), form-encoded. */
export function authorizationCodeTokenRequest(input: AuthorizationCodeTokenInput): HttpRequestMessage {
  return formPost(
    input.tokenEndpoint,
    { grant_type: AUTHORIZATION_CODE_GRANT, code: input.code, code_verifier: input.codeVerifier, redirect_uri: input.redirectUri, client_id: input.clientId },
    input,
  );
}

/** Nonce request (OpenID4VCI 1.0 section 7.1): a POST without body. */
export function nonceRequest(nonceEndpoint: string): HttpRequestMessage {
  return { method: 'POST', url: nonceEndpoint, headers: { accept: 'application/json' } };
}

export interface CredentialRequestInput {
  credentialEndpoint: string;
  accessToken: string;
  /** `token_type` of the token response; `DPoP` for a DPoP-bound token. */
  tokenType: string;
  dpop?: string;
  credentialConfigurationId: string;
  /** Request by this `credential_identifier` of the token response instead of `credential_configuration_id` (issue 20). */
  credentialIdentifier?: string;
  /** Key proofs of proof type `jwt`; left out for a configuration without proof types (issue 27). */
  proofs?: string[];
}

/** Credential request by `credential_configuration_id` with `proofs.jwt` (OpenID4VCI 1.0 section 8.2), JSON. */
export function credentialRequest(input: CredentialRequestInput): HttpRequestMessage {
  return {
    method: 'POST',
    url: input.credentialEndpoint,
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
      authorization: `${input.tokenType} ${input.accessToken}`,
      ...(input.dpop !== undefined ? { DPoP: input.dpop } : {}),
    },
    body: JSON.stringify({
      ...(input.credentialIdentifier !== undefined ? { credential_identifier: input.credentialIdentifier } : { credential_configuration_id: input.credentialConfigurationId }),
      ...(input.proofs ? { proofs: { jwt: input.proofs } } : {}),
    }),
  };
}

/** The Credential Issuer metadata as a signed JWT (OpenID4VCI 1.0 section 12.2.2). */
export function signedMetadataRequest(metadataUrl: string): HttpRequestMessage {
  return { method: 'GET', url: metadataUrl, headers: { accept: 'application/jwt' } };
}
