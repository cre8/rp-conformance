import type { Flow } from './definition';

/**
 * A default DCQL query of `default_configuration_rp_1`, see the FCAF defaults "Relying Party testing". Each default
 * query asks for its credential "in the credential format of the test case", so it has one variant per format: the
 * plain ID for SD-JWT VC and `…_mdoc` for mdoc. `…_trusted_authorities` is the variant of `default_query_pid`
 * restricted with a `trusted_authorities` entry of type `aki` naming the PID/Issuance anchor of `PP-A`
 * (TrustMechanisms_016). Test cases call each variant by its FCAF name, for example `default_query_pid`.
 */
export type DefaultQueryId =
  | 'default_query_pid'
  | 'default_query_pid_trusted_authorities'
  | 'default_query_pid_mdoc'
  | 'default_query_pid_mdoc_trusted_authorities'
  | 'default_query_qeaa'
  | 'default_query_qeaa_mdoc'
  | 'default_query_pubeaa'
  | 'default_query_pubeaa_mdoc'
  | 'default_query_eaa'
  | 'default_query_eaa_mdoc';

/** Every default query, in the order the adapters configure them. */
export const DEFAULT_QUERY_IDS: DefaultQueryId[] = [
  'default_query_pid',
  'default_query_pid_trusted_authorities',
  'default_query_pid_mdoc',
  'default_query_pid_mdoc_trusted_authorities',
  'default_query_qeaa',
  'default_query_qeaa_mdoc',
  'default_query_pubeaa',
  'default_query_pubeaa_mdoc',
  'default_query_eaa',
  'default_query_eaa_mdoc',
];

/**
 * The credential categories of the Relying Party SUT, each with its own root of trust in
 * `default_trust_configuration_rp`: PID (`TL-PID`), QEAA (`TL-QEAA`), PuB-EAA (`TL-PUB`) and non-qualified EAA (the
 * anchor its rulebook defines).
 */
export type CredentialCategory = 'pid' | 'qeaa' | 'pub-eaa' | 'eaa';

/** The category of the credential a default query asks for. */
export function categoryOfQuery(query: DefaultQueryId): CredentialCategory {
  if (query.startsWith('default_query_qeaa')) return 'qeaa';
  if (query.startsWith('default_query_pubeaa')) return 'pub-eaa';
  if (query.startsWith('default_query_eaa')) return 'eaa';
  return 'pid';
}

/** A certificate with its private key, as the harness hands it to the Relying Party under test. */
export interface KeyedCertificate {
  /** PEM of the certificate. */
  certificatePem: string;
  /** Base64 DER of the certificate, as used in `x5c`. */
  certificate: string;
  /** PEM of the certificate chain without the trust anchor, leaf first. */
  chainPem: string[];
  /** Private key as JWK (EC P-256). */
  privateJwk: JsonWebKey;
  /** Private key as PKCS#8 PEM. */
  privateKeyPem: string;
}

/** A list of `default_trust_configuration_rp` as published by the Test Trust Infrastructure. */
export interface PublishedTrustList {
  /** `TL-PID`, `TL-PUB`, `TL-WP`, `TL-AC` or `TL-RC`. */
  id: string;
  /** ETSI TS 119 602 `LoTEType`. */
  loteType: string;
  /** Where the Relying Party fetches the list. */
  url: string;
  /** The scheme operator certificate (PEM) the Relying Party trusts for this list. */
  schemeOperatorCertificatePem: string;
}

/**
 * The test list of trusted lists (ETSI TS 119 612, XML) that points to the test Trusted List `TL-QEAA`. The Relying
 * Party is configured with the LOTL's location and signing certificates only, the test counterpart of their publication
 * in the Official Journal, and takes `TL-QEAA` and the certificate that signs it from the LOTL's pointer.
 */
export interface PublishedListOfTrustedLists {
  url: string;
  /** PEM of the certificates that may sign the LOTL. */
  signingCertificatesPem: string[];
  /** The Trusted Lists the LOTL points to, for evidence; the Relying Party reads them from the LOTL. */
  pointers: { id: string; url: string; schemeTerritory: string }[];
}

/** A rulebook that defines its own trust anchor, as the rulebook of `default_credential_eaa` defines `CA-EP-A`. */
export interface RulebookTrust {
  /** The default credential the rulebook governs. */
  credential: 'default_credential_eaa';
  /** PEM of the anchors the rulebook defines, for signing the credential and its status lists. */
  anchorsPem: string[];
}

/**
 * Everything the Relying Party under test needs for `default_configuration_rp_1`: the scheme operator
 * certificates and URLs of the test lists, the test LOTL, the rulebook anchors, its access certificate and its
 * registration certificate.
 */
export interface TestEnvironment {
  runId: string;
  trustLists: PublishedTrustList[];
  /** The test LOTL that points to `TL-QEAA`. */
  listOfTrustedLists: PublishedListOfTrustedLists;
  /** The anchors the rulebook of `default_credential_eaa` defines. */
  rulebooks: RulebookTrust[];
  /** The Relying Party's access certificate issued by `AC-A`, with its key. */
  accessCertificate: KeyedCertificate;
  /** The Relying Party's registration certificate issued by `RC-A` (JWT, ETSI TS 119 475). */
  registrationCertificate: string;
  /** The DCQL queries of the default queries. */
  queries: Record<DefaultQueryId, DcqlQuery>;
  /** ICS values the adapter may pass to the Relying Party, for example `T_skew`. */
  ics: Ics;
}

export interface DcqlQuery {
  credentials: {
    id: string;
    format: string;
    meta?: Record<string, unknown>;
    claims?: { id?: string; path: (string | number | null)[] }[];
    require_cryptographic_holder_binding?: boolean;
    trusted_authorities?: { type: string; values: string[] }[];
  }[];
}

export type Outcome = 'success' | 'failure' | 'pending';

export interface RelyingPartyResult {
  outcome: Outcome;
  /** The attributes the Relying Party released to the relying service, by claim path joined with `.`. */
  releasedAttributes?: Record<string, unknown>;
  /** For example `status-unknown` or `trust-list-stale`. */
  flags?: string[];
  /** The Relying Party's own answer, kept as evidence. */
  raw: unknown;
}

export interface StartedPresentation {
  transactionId: string;
  invocation: { uri: string } | { dcApiPage: string };
}

/** The only Relying Party specific code of the harness (harness design section 4.8). */
export interface RelyingPartyAdapter {
  name: string;
  /** Host name under which the Relying Party reaches the harness services; default `127.0.0.1`. */
  harnessHost?: string;
  /** Configure the Relying Party: trust anchors, access and registration certificate, default queries. */
  setUp(env: TestEnvironment, namespace: string): Promise<void>;
  startPresentation(req: { query: DefaultQueryId; flow: Flow; namespace: string }): Promise<StartedPresentation>;
  readResult(transactionId: string, timeoutMs: number): Promise<RelyingPartyResult>;
  /** Optional: make the Relying Party fetch its trust lists now instead of waiting `T_refresh`. */
  refreshTrust?(namespace: string): Promise<void>;
  /** Optional: release resources the adapter started. */
  tearDown?(): Promise<void>;
}

/** Implementation Conformance Statement of a Relying Party, keyed by ICS item ID (see `ics-rp.md`). */
export interface Ics {
  /** For example `RP.G.1: Yes`, `RP.P.4: 60`. */
  items: Record<string, string | number | boolean>;
}
