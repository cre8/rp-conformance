import type { Flow } from './definition';

/**
 * A default DCQL query of `default_configuration_rp_1`, see the FCAF defaults "Relying Party testing".
 * `default_query_pid_trusted_authorities` is `default_query_pid` restricted with a `trusted_authorities` entry of type
 * `aki` naming the PID/Issuance anchor of `PP-A` (TrustMechanisms_016); test cases call it `default_query_pid`.
 */
export type DefaultQueryId = 'default_query_pid' | 'default_query_pid_trusted_authorities';

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
 * Everything the Relying Party under test needs for `default_configuration_rp_1`: the scheme operator
 * certificates and URLs of the test lists, its access certificate and its registration certificate.
 */
export interface TestEnvironment {
  runId: string;
  trustLists: PublishedTrustList[];
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
