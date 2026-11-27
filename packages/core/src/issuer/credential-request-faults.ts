// The named faults of the point `credential-request` (issuer harness design section 6.2): each is applied to the
// credential request after its valid build, and must fail exactly its `target` check of
// `validateCredentialRequest` (@eudi-pcaf/validator) and no other; `null` marks the one that must pass every check,
// since the catalogue expects `ISS` for it. `text` is the FCAF wording of the difference. The implementations are in
// packages/issuer-wallet/src/credential-request-faults.ts.
//
// Kept apart from `FAULTS` (../faults.ts) and from the faults of the points `wia`, `wia-pop`, `ka` and `proof`, so the
// RP suite's iteration over `FAULT_IDS` stays unchanged.
import type { CredentialRequestCheck } from './artifact-checks';

export interface CredentialRequestFaultInfo {
  point: 'credential-request';
  target: CredentialRequestCheck | null;
  /** The difference from the valid request, as the FCAF scenario words it (after "except that"). */
  text: string;
  /** The catalogue objectives (`issuer-test-catalogue.md` section 5.1.1) whose stimulus the fault is. */
  testCases: string[];
}

const CE = 'PP_WS_MS_CredentialEndpoint';
const fault = (target: CredentialRequestCheck | null, text: string, ...testCases: string[]): CredentialRequestFaultInfo => ({
  point: 'credential-request',
  target,
  text,
  testCases,
});

export const CREDENTIAL_REQUEST_FAULTS = {
  'credential-request.configuration-unknown': fault(
    'credential-request-configuration',
    'the `credential_configuration_id` of its credential request is a random value of 16 lowercase hexadecimal characters prefixed `unknown-`, which the Credential Issuer metadata does not offer',
    `${CE}_003_UF`,
  ),
  'credential-request.configuration-not-authorized': fault(
    'credential-request-authorized',
    'the `credential_configuration_id` of its credential request names a second configuration the Credential Issuer metadata offers, for which the offer and the access token were not issued',
    `${CE}_004_UF`,
  ),
  'credential-request.both-identifiers': fault(
    'credential-request-identifier',
    'its credential request carries the `credential_identifier` the token response issued for the configuration in addition to the `credential_configuration_id`',
    `${CE}_005_UF`,
  ),
  'credential-request.no-identifier': fault(
    'credential-request-identifier',
    'its credential request carries neither a `credential_identifier` nor a `credential_configuration_id`',
    `${CE}_005_UF`,
  ),
  'credential-request.identifier-foreign': fault(
    'credential-request-credential-identifier',
    'its credential request carries, instead of an identifier of its own token response, the `credential_identifier` the token response of another session issued',
    `${CE}_006_UF`,
  ),
  'credential-request.extra-member': fault(null, 'its credential request additionally carries the member `"foo": "bar"`, which OpenID4VCI does not define', `${CE}_007`),
} as const satisfies Record<string, CredentialRequestFaultInfo>;

export type CredentialRequestFaultId = keyof typeof CREDENTIAL_REQUEST_FAULTS;

export const CREDENTIAL_REQUEST_FAULT_IDS = Object.keys(CREDENTIAL_REQUEST_FAULTS) as CredentialRequestFaultId[];

export function isCredentialRequestFault(id: string): id is CredentialRequestFaultId {
  return id in CREDENTIAL_REQUEST_FAULTS;
}
