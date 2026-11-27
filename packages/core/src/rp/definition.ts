// The Relying Party part of a test definition: presentation flows, the `RP.*` ICS items, default credentials and
// queries, the step actions and expectation codes of the RP harness, and their builders.
import type { RequestCheck } from '../checks';
import {
  type CredentialFormat,
  controlsOf,
  type ExpectationOf,
  type IcsCondition,
  type StepDefinitionOf,
  type TestCaseDefinitionOf,
} from '../definition';
import { type FaultId, faultInfo } from '../faults';
import type { CredentialCategory, DefaultQueryId } from './adapter';

/** Presentation flows of the Relying Party SUT. */
export type Flow = 'redirect' | 'dc-api';

/** The ICS items of `ics-rp.md` that test cases use as `Profile applicability`, with their exact wording. */
export const ics = {
  requestsSdJwtVc: { item: 'RP.G.1', text: 'Relying Party requests credentials in IETF SD-JWT VC format.', equals: 'Yes' },
  requestsMdoc: { item: 'RP.G.2', text: 'Relying Party requests credentials in ISO/IEC 18013-5 mdoc format.', equals: 'Yes' },
  requestsQeaa: { item: 'RP.G.3', text: 'Relying Party requests QEAAs.', equals: 'Yes' },
  requestsPubEaa: { item: 'RP.G.4', text: 'Relying Party requests PuB-EAAs.', equals: 'Yes' },
  requestsEaa: { item: 'RP.G.5', text: 'Relying Party requests non-qualified EAAs.', equals: 'Yes' },
  supportsRedirects: { item: 'RP.P.1', text: 'Relying Party supports presentations via redirects.', equals: 'Yes' },
  supportsDcApi: { item: 'RP.P.2', text: 'Relying Party supports presentations via the W3C Digital Credentials API.', equals: 'Yes' },
  usesTrustedAuthorities: { item: 'RP.P.3', text: 'Relying Party uses `trusted_authorities` in DCQL queries.', equals: 'Yes' },
  appliesClockTolerance: { item: 'RP.P.5', text: 'Relying Party applies a clock tolerance greater than zero.', equals: 'Yes' },
  checksPidRevocation: { item: 'RP.R.1', text: 'Relying Party checks the revocation status of PIDs.', equals: 'Yes' },
  checksAttestationRevocation: {
    item: 'RP.R.9',
    text: 'Relying Party checks the revocation status of QEAAs, PuB-EAAs and non-qualified EAAs.',
    equals: 'Yes',
  },
  appliesGracePeriod: {
    item: 'RP.T.3',
    text: 'Relying Party keeps using a trust list for a grace period greater than zero after its `NextUpdate`.',
    equals: 'Yes',
  },
  cachesStatusLists: { item: 'RP.R.5', text: 'Relying Party caches Status List Tokens.', equals: 'Yes' },
  usesRequestUriPost: { item: 'RP.P.8', text: 'Relying Party sets `request_uri_method` to `post`.', equals: 'Yes' },
  redeemsResponseCode: {
    item: 'RP.P.9',
    text: 'Relying Party redeems the response code of a presentation via redirects at its own front end.',
    equals: 'Yes',
  },
  bindsByAttributes: {
    item: 'RP.P.10',
    text: 'Relying Party binds the credentials of a combined presentation by comparing their identifying attributes (attribute-based binding).',
    equals: 'Yes',
  },
} as const satisfies Record<string, IcsCondition>;

/** The ICS items that declare support for a flow. */
export const flowIcsItems: Record<Flow, string> = {
  redirect: ics.supportsRedirects.item,
  'dc-api': ics.supportsDcApi.item,
};

/** Every presentation flow, in the order the controller runs them. */
export const FLOWS: Flow[] = ['redirect', 'dc-api'];

/**
 * The FCAF default credentials the Test Issuers issue: the PID, the PID valid for less than 24 hours without status,
 * and `default_credential_A` issued as a QEAA, a PuB-EAA or a non-qualified EAA.
 */
export type DefaultCredential =
  | 'default_credential_pid'
  | 'default_credential_pid_short'
  | 'default_credential_qeaa'
  | 'default_credential_pubeaa'
  | 'default_credential_eaa';

/** The default credential of each category, and the entity of `default_trust_configuration_rp` that issues it. */
export const DEFAULT_CREDENTIALS: Record<CredentialCategory, { credential: DefaultCredential; issuer: string }> = {
  pid: { credential: 'default_credential_pid', issuer: 'PP-A' },
  qeaa: { credential: 'default_credential_qeaa', issuer: 'QP-A' },
  'pub-eaa': { credential: 'default_credential_pubeaa', issuer: 'PB-A' },
  eaa: { credential: 'default_credential_eaa', issuer: 'EP-A' },
};

/** The category of a default credential. */
export function categoryOfCredential(credential: DefaultCredential): CredentialCategory {
  const entry = Object.entries(DEFAULT_CREDENTIALS).find(([, value]) => value.credential === credential);
  return (entry?.[0] as CredentialCategory | undefined) ?? 'pid';
}

/** A credential the Test Issuers issue for a step, valid unless a fault is applied. */
export interface CredentialSpec {
  /** The FCAF default credential; `default_credential_pid_short` is valid for less than 24 hours and has no status. */
  defaultCredential: DefaultCredential;
  format: CredentialFormat;
  /** Entity of `default_trust_configuration_rp` that issues the credential. */
  issuer: string;
  /** The anchor of the issuer the signing certificate is under; default `issuance` (`revocation`: TrustMechanisms_004). */
  signedUnder?: 'issuance' | 'revocation';
  /** Named faults (at most one); empty for a valid credential. */
  faults: FaultId[];
  /** A PID whose administrative expiry date (`date_of_expiry`, mdoc `expiry_date`) lies seven days in the past. */
  expiryDatePast?: boolean;
  /**
   * `default_credential_A` only (UC_Presentation_010, _011): the credential additionally carries the identifying
   * attributes family name, given name and birth date, of the holder of `default_credential_pid` (`holder`) or of
   * another person (`other-person`).
   */
  identifying?: 'holder' | 'other-person';
}

/** A Status List Token the Test Status Provider serves for the step's credential: JWT for SD-JWT VC, CWT for mdoc. */
export interface StatusListSpec {
  format: 'jwt' | 'cwt';
  /** Status value at the credential's index; 0 is VALID. */
  status: number;
  /** Status value of every other entry; default 0. */
  others?: number;
  /** Bits per status; default 1 for the values 0 and 1, otherwise 2. */
  bits?: 1 | 2 | 4 | 8;
  /** The credential's index; default random. */
  index?: number;
  /** Signer: an entity's revocation signer (default: the credential's issuer), or its issuance signer, the credential's own. */
  signer?: { entity: string; key: 'revocation' | 'issuance' };
  /** Named faults (at most one); empty for a valid token. */
  faults: FaultId[];
  /** The `ttl` claim, seconds; default 300. */
  ttl?: number;
  /** The credential references the status list URI of this earlier step (1-based) instead of a new one. */
  uriOfStep?: number;
  /** How the Test Status Provider answers for the status list; default: it serves the token. */
  endpoint?: StatusEndpoint;
}

/**
 * How the Test Status Provider answers for a status list (RP_PP_IA_Supportive): with an HTTP status (and optionally
 * another body and content type), with the valid token only after the Relying Party's declared timeout (ICS RP.R.6)
 * plus ten seconds, with a redirect to the same URI, or not at all: `refused` puts the URI at a port of the harness
 * host on which nothing listens, `address` makes the credential reference `uri`, which the harness never requests.
 */
export type StatusEndpoint =
  | { kind: 'status'; status: number; contentType?: string; body?: string }
  | { kind: 'slow' }
  | { kind: 'redirect-loop' }
  | { kind: 'refused' }
  | { kind: 'address'; uri: string };

/**
 * An identifier list (ISO/IEC 18013-5 second edition section 12.3.6.4, CWT) the Test Status Provider serves for the
 * step's mdoc, whose MSO then references it with an `identifier_list` entry instead of a `status_list` entry.
 */
export interface IdentifierListSpec {
  format: 'cwt';
  /** Whether the list contains the credential's identifier (the credential is revoked). */
  contains: boolean;
  /** Named faults (at most one); empty for a valid list. */
  faults: FaultId[];
}

/**
 * The Authorization Response the Conformance Wallet sends, with the presentation it builds for the request: the KB-JWT
 * of an SD-JWT VC, the DeviceAuth of an mdoc.
 */
export interface ResponseSpec {
  /** Content encryption; default the first of the request's `encrypted_response_enc_values_supported` the wallet supports. */
  enc?: 'A128GCM' | 'A256GCM';
  /** Named faults (at most one) of the response or of the presentation in it; empty for a valid response. */
  faults: FaultId[];
  /** For `response.other-transaction-key`: the step (1-based) whose transaction's encryption key is used. */
  keyOfStep?: number;
  /** For `presentation.replay`: the step (1-based) whose presentation the `vp_token` carries again. */
  presentationOfStep?: number;
}

/** Start a presentation, present a credential and send the Authorization Response. */
export interface PresentationAction {
  kind: 'presentation';
  query: DefaultQueryId;
  credential: CredentialSpec;
  /** The Status List Token of the credential; `null` when the credential has no status list reference. */
  statusList: StatusListSpec | null;
  /** The identifier list of an mdoc; left out or `null` when it has none. */
  identifierList?: IdentifierListSpec | null;
  response: ResponseSpec;
  /** Seconds the controller waits after the Test Status Provider serves the step's list, before the presentation starts. */
  delaySeconds?: number;
  /** How the Conformance Wallet deviates from the plain flow (catalogue scenario SCN-F); left out for the plain flow. */
  wallet?: WalletBehaviour;
  /**
   * The `id` of the credential query `credential` answers; default the first credential query of the query in its
   * format. Named by the steps of a combined presentation (UC_Presentation).
   */
  answers?: string;
  /**
   * Further credentials the Conformance Wallet presents in the same Authorization Response, each for its own
   * credential query (UC_Presentation). Faults of the response or presentation apply to `credential`.
   */
  alongside?: AlongsideCredential[];
}

/** A credential presented in a combined presentation besides the step's `credential`. */
export interface AlongsideCredential {
  /** The `id` of the credential query it answers. */
  answers: string;
  credential: CredentialSpec;
  /** Its Status List Token; `null` when it has no status list reference. */
  statusList: StatusListSpec | null;
}

/** Start a presentation and fetch its request, but send no response (SessionEncryption_005, transaction T1). */
export interface StartAction {
  kind: 'start';
  query: DefaultQueryId;
}

/** The trust lists a step can publish a new version of: the PID Provider LoTE and the Trusted List of QTSPs. */
export type PublishableList = 'TL-PID' | 'TL-QEAA';

/**
 * Publish a new version of a trust list and wait until the Relying Party retrieved it (TrustMechanisms_007, _008,
 * RP_Inf_SM_TrustMechanisms). The version differs from the current one in the entities it removes or adds, the
 * withdrawn PID/Issuance services it lists again, the QTSP services it grants, and at most one trust-list fault.
 */
export interface TrustListAction {
  kind: 'trust-list';
  list: PublishableList;
  remove?: string[];
  add?: string[];
  /** `TL-PID`: entities whose withdrawn PID/Issuance service the version lists again (`PP-W`, RP_Inf_005). */
  restoreIssuance?: string[];
  /** `TL-QEAA`: entities whose service the version lists as a granted qualified service (`QP-N`, RP_Inf_009). */
  grantQualified?: string[];
  /** Named trust-list faults (at most one); empty or left out for a valid version. */
  faults?: FaultId[];
}

/**
 * Start `count` presentations for a default query and capture their requests at the Conformance Wallet, without
 * answering them (catalogue scenario SCN-Q). The step's `CONF` expectation names the request checks they must pass.
 */
export interface RequestAction {
  kind: 'request';
  query: DefaultQueryId;
  /** Number of requests; default 1. Freshness checks compare them with each other. */
  count?: number;
  /**
   * How the Conformance Wallet retrieves the request object: `twice` with GET (ProtocolFlow_002), or with POST,
   * `wallet_metadata` and `wallet_nonce` (`post`, ProtocolFlow_003); default once with GET.
   */
  requestUri?: 'twice' | 'post';
}

export type StepAction = PresentationAction | StartAction | TrustListAction | RequestAction | FlowAction | ErrorResponseAction;

/**
 * Expected-result codes of the catalogue (harness design section 5). `LIST_RETRIEVED`: the Test Trust Infrastructure
 * logged a retrieval of the list version the step published. `ENC_KEY`: the request carries an encryption key in its
 * `client_metadata`. `REJ_OR_ACC`: the Relying Party rejects the presentation, or accepts it and releases exactly the
 * requested attributes with their issuer-signed values (DeviceBinding_011: a device-signed element is ignored).
 * `STALE`: the verification result signals that a trust list it depends on is stale (`trust-list-stale`). `CONF`: the
 * captured requests pass the request checks the expectation names. `REJ_OR_INVALID`: the Relying Party rejects the
 * presentation, or accepts it and flags an attribute as invalid (`attribute-invalid`, IdentifyingData_004).
 */
export type ExpectationCode =
  | 'ACC'
  | 'REJ'
  | 'REJ_OR_ACC'
  | 'NOSTAT'
  | 'NOFETCH'
  | 'FETCHED'
  | 'POLICY'
  | 'LIST_RETRIEVED'
  | 'ENC_KEY'
  | 'STALE'
  | 'CONF'
  | RobustnessExpectationCode
  | RetrievalExpectationCode
  | InformativeExpectationCode
  | FlowExpectationCode
  | 'REJ_OR_INVALID';

/**
 * Expected-result codes of `RP_WS_SH_Encoding`: `HTTP_4XX`, the `response_uri` answers the Authorization Response with
 * HTTP 4xx; `NO_DETAILS`, that answer reveals no internal details (stack traces, source paths, exception names). Via the
 * W3C Digital Credentials API the response returns to the Relying Party's own page, so both apply to redirects only.
 */
export type RobustnessExpectationCode = 'HTTP_4XX' | 'NO_DETAILS';

/**
 * Expected-result code of `RP_PP_IA_Supportive`: `STATUS_REQUEST`, every request the Test Status Provider logged for the
 * step's status list is a `GET` of exactly its URI without authentication, cookies or the transaction's identifier,
 * with an `Accept` header, if any, that admits the token's media type.
 */
export type RetrievalExpectationCode = 'STATUS_REQUEST';

/** `INFO` (catalogue section 2.5): the outcome is recorded in the report, without a verdict on it. */
export type InformativeExpectationCode = 'INFO';

/**
 * The ICS declaration a `POLICY` expectation is compared with: `RP.R.3`, the meaning the Relying Party assigns to an
 * application-specific status value; `RP.R.7`, the maximum age of a Status List Token, for a token `ageSeconds` old;
 * `RP.R.8`, whether it refuses a Status List Token issued in the future; `RP.P.12`, its policy for a PID whose
 * administrative expiry date has passed; `RP.P.13` and `RP.P.14`, whether it applies a check for which the traces in
 * rp-test-catalogue.md section 8.4 find no requirement (issue 10).
 */
export type PolicyReference =
  | {
      /** `RP.R.3`: the meaning the Relying Party assigns to an application-specific status value. */
      item: 'RP.R.3';
      status: number;
    }
  | { item: 'RP.R.7'; ageSeconds: number }
  | { item: 'RP.R.8' }
  | { item: 'RP.P.12' }
  /** `RP.T.4`: whether the Relying Party keeps the last valid version of a trust list after a new version fails its seal. */
  | { item: 'RP.T.4' }
  /** `RP.P.13`: whether the Relying Party rejects an SD-JWT VC whose signing certificate does not name its `iss` (a URI SAN equal to it, or, with no URI SAN, a DNS SAN equal to its host as a URL parser gives it; without `iss`, no check). */
  | { item: 'RP.P.13' }
  /** `RP.P.14`: whether the Relying Party rejects an mdoc whose IssuerAuth declares `ES384` (-35) over a P-256 document signer key. */
  | { item: 'RP.P.14' };

/** An expected result of an RP test case. */
export interface Expectation extends ExpectationOf<ExpectationCode> {
  /** For `POLICY`: the ICS item that decides between accepting and rejecting. */
  policy?: PolicyReference;
  /** For `CONF`: the request checks the captured requests must pass. */
  checks?: RequestCheck[];
  /**
   * For `REJ` via the W3C Digital Credentials API: the page's request that forwards the response failing with a network
   * error also counts as a rejection, whatever the verification result says (`RP_WS_SH_Encoding_004_UF`: a server that
   * refuses an oversized body with HTTP 413 before its CORS headers are set leaves the page only a network error).
   */
  forwardFailureRejects?: true;
}

/** One step of an RP test case. */
export type StepDefinition = StepDefinitionOf<StepAction, Expectation>;

/** An executable RP test definition (harness design section 4.2). */
export interface TestCaseDefinition extends TestCaseDefinitionOf<StepDefinition> {
  /**
   * `RP_<class>_<layer>_<area>_<nnn><variant>[<category>][_UF]`; class, layer and area also give the file location. The
   * category variant `Q`, `PB` or `E` is that of class `RP_AP` only.
   */
  id: string;
}

/** The category variant of an `RP_AP` test case (catalogue section 2.1): QEAA, PuB-EAA or non-qualified EAA. */
export type AttestationVariant = 'Q' | 'PB' | 'E';

/** The credential category of each category variant. */
export const ATTESTATION_VARIANT_CATEGORY: Record<AttestationVariant, Exclude<CredentialCategory, 'pid'>> = {
  Q: 'qeaa',
  PB: 'pub-eaa',
  E: 'eaa',
};

export interface TestCaseId {
  sutClass: 'WS' | 'PP' | 'AP' | 'Inf';
  layer: string;
  area: string;
  number: number;
  variant: string;
  /** The category variant of an `RP_AP` test case. */
  category?: AttestationVariant;
  unhappyFlow: boolean;
}

const TEST_CASE_ID = /^RP_(WS|PP|AP|Inf)_([A-Z]{2})_([A-Za-z]+)_(\d{3})([a-z]?)(Q|PB|E)?(_UF)?$/;

/** Parses a Relying Party test case ID, for selection and for the renderer's file layout. */
export function parseTestCaseId(id: string): TestCaseId {
  const match = TEST_CASE_ID.exec(id);
  if (!match) throw new Error(`${id} is not a Relying Party test case ID`);
  if ((match[1] === 'AP') !== Boolean(match[6])) throw new Error(`${id}: a category variant belongs to class RP_AP, and every RP_AP test case has one`);
  return {
    sutClass: match[1] as TestCaseId['sutClass'],
    layer: match[2],
    area: match[3],
    number: Number(match[4]),
    variant: match[5],
    ...(match[6] ? { category: match[6] as AttestationVariant } : {}),
    unhappyFlow: Boolean(match[7]),
  };
}

/**
 * The presentation flows a test case is executed in: the flow its `Profile applicability` names (the
 * `SessionEncryption` variants), otherwise every flow, as the comment "Execute this test case once for each
 * presentation flow the Relying Party supports" instructs.
 */
export function flowsOf(definition: TestCaseDefinition): Flow[] {
  const named = FLOWS.filter((flow) => definition.profile.some((condition) => condition.item === flowIcsItems[flow]));
  return named.length ? named : FLOWS;
}

const CONTROL_MENTION = /`(RP_WS_(?:IA_MainInteraction|UC_Presentation)_\d{3}[a-z]?)`/g;

/**
 * Checks a definition so the rendered test case and the executed one cannot disagree: a valid ID, at least one step,
 * and the `control` that gates execution is exactly the set of positive controls the preconditions name.
 */
export function defineTestCase(definition: TestCaseDefinition): TestCaseDefinition {
  parseTestCaseId(definition.id);
  if (definition.steps.length === 0) throw new Error(`${definition.id}: a test case needs at least one step`);
  const named = new Set(definition.preconditions.flatMap((p) => [...p.matchAll(CONTROL_MENTION)].map((m) => m[1])));
  const gated = new Set(controlsOf(definition));
  if (named.size !== gated.size || [...named].some((id) => !gated.has(id))) {
    throw new Error(
      `${definition.id}: control (${[...gated].join(', ') || 'none'}) differs from the controls the preconditions name (${[...named].join(', ') || 'none'})`,
    );
  }
  return definition;
}

export function step(definition: StepDefinition): StepDefinition {
  return definition;
}

/** The status list format of a credential format: JWT for SD-JWT VC, CWT for mdoc. */
export const statusListFormatOf = (format: CredentialFormat): StatusListSpec['format'] => (format === 'mso_mdoc' ? 'cwt' : 'jwt');

/**
 * A presentation step. Without `statusList` the credential references a valid Status List Token in the format that
 * belongs to its own (none for `default_credential_pid_short`, nor for an mdoc that references an identifier list).
 * Refuses more than one fault, a fault at another point, and a fault or list in another format.
 */
export function presentation(
  action: Omit<PresentationAction, 'kind' | 'statusList' | 'response' | 'alongside'> & {
    statusList?: StatusListSpec | null;
    response?: ResponseSpec;
    alongside?: (Omit<AlongsideCredential, 'statusList'> & { statusList?: StatusListSpec | null })[];
  },
): PresentationAction {
  const { credential } = action;
  const withoutStatus = credential.defaultCredential === 'default_credential_pid_short' || Boolean(action.identifierList);
  const statusList =
    action.statusList === undefined ? (withoutStatus ? null : statusListToken.of(statusListFormatOf(credential.format))) : action.statusList;
  const alongside = action.alongside?.map(
    (other): AlongsideCredential => ({
      ...other,
      statusList: other.statusList === undefined ? statusListToken.of(statusListFormatOf(other.credential.format)) : other.statusList,
    }),
  );
  const { alongside: _alongside, ...rest } = action;
  const result: PresentationAction = {
    kind: 'presentation',
    ...rest,
    statusList,
    response: action.response ?? { faults: [] },
    ...(alongside ? { alongside } : {}),
  };
  for (const other of alongside ?? []) {
    if (other.statusList && other.statusList.format !== statusListFormatOf(other.credential.format)) {
      throw new Error(`a ${other.credential.format} credential references a Status List Token in ${statusListFormatOf(other.credential.format)} format`);
    }
    for (const fault of [...other.credential.faults, ...(other.statusList?.faults ?? [])]) {
      const info = faultInfo(fault);
      if (info.point !== 'credential' && info.point !== 'status-list') throw new Error(`fault ${fault} does not apply to the credential or its status list`);
    }
  }
  const faults = faultsOf(result);
  if (faults.length > 1) throw new Error(`a step applies one fault, not ${faults.join(', ')}`);
  if (result.statusList && result.statusList.format !== statusListFormatOf(credential.format)) {
    throw new Error(`a ${credential.format} credential references a Status List Token in ${statusListFormatOf(credential.format)} format`);
  }
  if (result.identifierList && credential.format !== 'mso_mdoc') throw new Error('only an mdoc references an identifier list');
  for (const [fault, points, format] of [
    ...credential.faults.map((f) => [f, ['credential'], credential.format] as const),
    ...(result.statusList?.faults ?? []).map((f) => [f, ['status-list'], result.statusList?.format] as const),
    ...(result.identifierList?.faults ?? []).map((f) => [f, ['identifier-list'], 'cwt'] as const),
    // The presentation travels in the response; a presentation fault applies to the credential's format.
    ...result.response.faults.map(
      (f) => [f, ['response', 'presentation', 'vp-token'], faultInfo(f).point === 'response' ? undefined : credential.format] as const,
    ),
  ]) {
    const info = faultInfo(fault);
    if (!(points as readonly string[]).includes(info.point)) throw new Error(`fault ${fault} does not apply to the ${points.join(' or ')}`);
    if (info.format && info.format !== format) throw new Error(`fault ${fault} applies to ${info.format}, not ${format}`);
    if (info.issuer && info.issuer !== credential.issuer) throw new Error(`fault ${fault} needs a credential issued by ${info.issuer}`);
    if (info.query && info.query !== result.query) throw new Error(`fault ${fault} is presented for ${info.query}, not ${result.query}`);
  }
  const replays = result.response.faults.includes('presentation.replay');
  if (replays !== (result.response.presentationOfStep !== undefined)) {
    throw new Error('presentation.replay and presentationOfStep go together');
  }
  return result;
}

/** The curve of the Conformance Wallet key a step's credential is bound to: P-256, or secp256k1 for an `ES256K` fault. */
export function holderCurveOf(action: StepAction): 'P-256' | 'secp256k1' {
  return faultsOf(action).some((fault) => faultInfo(fault).holderCurve === 'secp256k1') ? 'secp256k1' : 'P-256';
}

/** Every fault of a presentation. */
export function faultsOf(action: StepAction): FaultId[] {
  if (action.kind === 'trust-list') return action.faults ?? [];
  if (action.kind !== 'presentation') return [];
  return [
    ...action.credential.faults,
    ...(action.statusList?.faults ?? []),
    ...(action.identifierList?.faults ?? []),
    ...action.response.faults,
    ...(action.alongside ?? []).flatMap((other) => [...other.credential.faults, ...(other.statusList?.faults ?? [])]),
  ];
}

/** The default query for a PID in `format`, optionally the variant restricted with `trusted_authorities`. */
export function pidQueryOf(format: CredentialFormat, options: { trustedAuthorities?: boolean } = {}): DefaultQueryId {
  const base = format === 'mso_mdoc' ? 'default_query_pid_mdoc' : 'default_query_pid';
  return (options.trustedAuthorities ? `${base}_trusted_authorities` : base) as DefaultQueryId;
}

const QUERY_BASE: Record<CredentialCategory, string> = {
  pid: 'default_query_pid',
  qeaa: 'default_query_qeaa',
  'pub-eaa': 'default_query_pubeaa',
  eaa: 'default_query_eaa',
};

/** The default query for the credential of a category in `format`: `default_query_qeaa` or `default_query_qeaa_mdoc`, … */
export function queryOf(category: CredentialCategory, format: CredentialFormat): DefaultQueryId {
  return `${QUERY_BASE[category]}${format === 'mso_mdoc' ? '_mdoc' : ''}` as DefaultQueryId;
}

export interface PidOptions {
  issuer?: string;
  signedUnder?: 'issuance' | 'revocation';
  faults?: FaultId[];
}

/** Builders for the default credentials. */
export const pid = {
  /** `default_credential_pid` in `format`, issued by `PP-A`. */
  of(format: CredentialFormat, options: PidOptions = {}): CredentialSpec {
    return {
      defaultCredential: 'default_credential_pid',
      format,
      issuer: options.issuer ?? 'PP-A',
      ...(options.signedUnder ? { signedUnder: options.signedUnder } : {}),
      faults: options.faults ?? [],
    };
  },
  /** `default_credential_pid_short` in `format`: valid for less than 24 hours, without status reference. */
  shortOf(format: CredentialFormat): CredentialSpec {
    return { defaultCredential: 'default_credential_pid_short', format, issuer: 'PP-A', faults: [] };
  },
  /** `default_credential_pid` in SD-JWT VC format, issued by `PP-A`. */
  sdJwtVc(options: PidOptions = {}): CredentialSpec {
    return pid.of('dc+sd-jwt', options);
  },
  /** `default_credential_pid_short` in SD-JWT VC format: valid for less than 24 hours, without status reference. */
  shortSdJwtVc(): CredentialSpec {
    return pid.shortOf('dc+sd-jwt');
  },
  /** `default_credential_pid` in mdoc format (`eu.europa.ec.eudi.pid.1`), issued by `PP-A`. */
  mdoc(options: PidOptions = {}): CredentialSpec {
    return pid.of('mso_mdoc', options);
  },
  /** `default_credential_pid_short` in mdoc format. */
  shortMdoc(): CredentialSpec {
    return pid.shortOf('mso_mdoc');
  },
};

export interface AttestationOptions {
  /** Default: the entity that issues the category's default credential (`QP-A`, `PB-A`, `EP-A`). */
  issuer?: string;
  faults?: FaultId[];
  /** UC_Presentation_010, _011: the credential also carries identifying attributes (`CredentialSpec.identifying`). */
  identifying?: CredentialSpec['identifying'];
}

/**
 * Builders for `default_credential_A` issued as a QEAA, a PuB-EAA or a non-qualified EAA: device-bound and with
 * revocation information as for `default_credential_pid`.
 */
export const attestation = {
  of(category: Exclude<CredentialCategory, 'pid'>, format: CredentialFormat, options: AttestationOptions = {}): CredentialSpec {
    const { credential, issuer } = DEFAULT_CREDENTIALS[category];
    return {
      defaultCredential: credential,
      format,
      issuer: options.issuer ?? issuer,
      faults: options.faults ?? [],
      ...(options.identifying ? { identifying: options.identifying } : {}),
    };
  },
};

export const statusListToken = {
  /** A Status List Token in `format` holding `status` (default 0x00, VALID) at the credential's index. */
  of(format: StatusListSpec['format'], options: Partial<Omit<StatusListSpec, 'format'>> = {}): StatusListSpec {
    return { format, ...options, status: options.status ?? 0, faults: options.faults ?? [] };
  },
  /** A Status List Token in JWT format, for an SD-JWT VC. */
  jwt(options: Partial<Omit<StatusListSpec, 'format'>> = {}): StatusListSpec {
    return statusListToken.of('jwt', options);
  },
  /** A Status List Token in CWT format, for an mdoc. */
  cwt(options: Partial<Omit<StatusListSpec, 'format'>> = {}): StatusListSpec {
    return statusListToken.of('cwt', options);
  },
};

export const identifierListToken = {
  /** An identifier list in CWT format that contains, or does not contain, the mdoc's identifier. */
  cwt(options: { contains: boolean; faults?: FaultId[] }): IdentifierListSpec {
    return { format: 'cwt', contains: options.contains, faults: options.faults ?? [] };
  },
};


/**
 * How the Conformance Wallet deviates from the plain flow of a presentation step (catalogue scenario SCN-F,
 * `RP_WS_IA_ProtocolFlow`).
 */
export interface WalletBehaviour {
  /**
   * Via redirects, what happens with the `redirect_uri` the Relying Party returns: the wallet opens it without the
   * user agent's session (default), or does not open it (`none`), so a later step can open it in a user agent.
   */
  redirect?: 'none';
  /** Send the Authorization Response only after the transaction lifetime `T_tx` (ICS RP.P.7) passed since the start. */
  late?: boolean;
}

/**
 * Continues the transaction of an earlier step (catalogue scenario SCN-F): retrieve its `request_uri` again
 * (`request-uri-again`) or that of an unknown transaction (`request-uri-unknown`, the transaction-specific part
 * replaced), send its Authorization Response again (`resend`), ask the Relying Party's front end for its result in the
 * user agent that started it without following the redirect (`front-end`), or open its `redirect_uri` in that user
 * agent (`redirect-same`), in a fresh one (`redirect-fresh`), or with a random response code (`redirect-forged`).
 */
export interface FlowAction {
  kind: 'flow';
  /** The step (1-based) whose transaction the action continues. */
  ofStep: number;
  behaviour: FlowBehaviour;
}

export type FlowBehaviour =
  | 'request-uri-again'
  | 'request-uri-unknown'
  | 'resend'
  | 'front-end'
  | 'redirect-same'
  | 'redirect-fresh'
  | 'redirect-forged';

/**
 * Start a presentation and answer it with an Authorization Error Response of the Conformance Wallet instead of a
 * presentation: unencrypted via redirects (OpenID4VP section 8.5), an error object via the DC API (Appendix A.4).
 */
export interface ErrorResponseAction {
  kind: 'error-response';
  query: DefaultQueryId;
  error: 'access_denied' | 'invalid_request';
}

/**
 * Expected-result codes of the flow test cases (`RP_WS_IA_ProtocolFlow`). `REDIRECT`: the `response_uri` answered
 * HTTP 200 `application/json` with a `redirect_uri` carrying a fresh `response_code` of at least 128 bits.
 * `RELEASED`: the Relying Party's front end released the attributes of the transaction to the user agent. `WITHHELD`:
 * it released nothing. `REQUEST_REFUSED`: `request_uri` answered HTTP 4xx without a request object. `ERROR_ACK`: the
 * `response_uri` answered the error response with HTTP 200 `application/json`. `RESEND_REJ`: the `response_uri`
 * answered the second Authorization Response with HTTP 4xx, and the verification result of the transaction is
 * unchanged.
 */
export type FlowExpectationCode = 'REDIRECT' | 'RELEASED' | 'WITHHELD' | 'REQUEST_REFUSED' | 'ERROR_ACK' | 'RESEND_REJ';

/** The expectation codes evaluated by the flow module of the controller. */
export const FLOW_EXPECTATION_CODES: readonly FlowExpectationCode[] = ['REDIRECT', 'RELEASED', 'WITHHELD', 'REQUEST_REFUSED', 'ERROR_ACK', 'RESEND_REJ'];
