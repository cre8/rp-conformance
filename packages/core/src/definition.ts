import type { DefaultQueryId } from './adapter';
import { type FaultId, faultInfo } from './faults';

/** Presentation flows of the Relying Party SUT. */
export type Flow = 'redirect' | 'dc-api';

/** FCAF test case verdicts. */
export type Verdict = 'PASS' | 'FAIL' | 'INCONCLUSIVE' | 'NOT APPLICABLE' | 'REVIEW';

/** A condition of the `Profile applicability` section, evaluated against the Relying Party ICS. */
export interface IcsCondition {
  /** ICS item ID, for example `RP.G.1`. */
  item: string;
  /** The text of the ICS item in `ics-rp.md`, rendered as the profile applicability line. */
  text: string;
  /** The answer that makes the test case applicable. */
  equals: string;
}

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
} as const satisfies Record<string, IcsCondition>;

/** The ICS items that declare support for a flow. */
export const flowIcsItems: Record<Flow, string> = {
  redirect: ics.supportsRedirects.item,
  'dc-api': ics.supportsDcApi.item,
};

/** `EUDI-wallet relevancy` values of the FCAF methodology. */
export const relevancy = {
  genericRequired: 'EUDI_generic | EUDI_required',
  genericOptional: 'EUDI_generic | EUDI_optional',
  genericUndefined: 'EUDI_generic | EUDI_undefined',
  specificRequired: 'EUDI_specific | EUDI_required',
  specificOptional: 'EUDI_specific | EUDI_optional',
} as const;

export type Relevancy = (typeof relevancy)[keyof typeof relevancy];

/** Credential formats of the Relying Party SUT (OpenID4VP format identifiers). */
export type CredentialFormat = 'dc+sd-jwt' | 'mso_mdoc';

/** A credential the Test Issuers issue for a step, valid unless a fault is applied. */
export interface CredentialSpec {
  /** The FCAF default credential: `default_credential_pid`, or `default_credential_pid_short` (under 24 hours, no status). */
  defaultCredential: 'default_credential_pid' | 'default_credential_pid_short';
  format: CredentialFormat;
  /** Entity of `default_trust_configuration_rp` that issues the credential. */
  issuer: string;
  /** The anchor of the issuer the signing certificate is under; default `issuance` (`revocation`: TrustMechanisms_004). */
  signedUnder?: 'issuance' | 'revocation';
  /** Named faults (at most one); empty for a valid credential. */
  faults: FaultId[];
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
}

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

/** The Authorization Response the Conformance Wallet sends. */
export interface ResponseSpec {
  /** Content encryption; default the first of the request's `encrypted_response_enc_values_supported` the wallet supports. */
  enc?: 'A128GCM' | 'A256GCM';
  /** Named faults (at most one); empty for a valid response. */
  faults: FaultId[];
  /** For `response.other-transaction-key`: the step (1-based) whose transaction's encryption key is used. */
  keyOfStep?: number;
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
}

/** Start a presentation and fetch its request, but send no response (SessionEncryption_005, transaction T1). */
export interface StartAction {
  kind: 'start';
  query: DefaultQueryId;
}

/** Publish a new version of a trust list and wait until the Relying Party retrieved it (TrustMechanisms_007, _008). */
export interface TrustListAction {
  kind: 'trust-list';
  list: 'TL-PID';
  remove?: string[];
  add?: string[];
}

export type StepAction = PresentationAction | StartAction | TrustListAction;

/**
 * Expected-result codes of the catalogue (harness design section 5). `LIST_RETRIEVED`: the Test Trust Infrastructure
 * logged a retrieval of the list version the step published. `ENC_KEY`: the request carries an encryption key in its
 * `client_metadata`.
 */
export type ExpectationCode = 'ACC' | 'REJ' | 'NOSTAT' | 'NOFETCH' | 'FETCHED' | 'POLICY' | 'LIST_RETRIEVED' | 'ENC_KEY';

/** The ICS declaration a `POLICY` expectation is compared with. */
export interface PolicyReference {
  /** `RP.R.3`: the meaning the Relying Party assigns to an application-specific status value. */
  item: 'RP.R.3';
  status: number;
}

/** An expected result: the codes the controller evaluates and the FCAF text it renders. */
export interface Expectation {
  codes: ExpectationCode[];
  text: string;
  /** For `POLICY`: the ICS item that decides between accepting and rejecting. */
  policy?: PolicyReference;
}

/** One line of `Test Scenario` with its line of `Expected results`, and what the harness executes for it. */
export interface StepDefinition {
  /** Test scenario text of the step. */
  text: string;
  /** What the harness executes; left out while the step is text only (a later phase makes it executable). */
  run?: StepAction;
  expect: Expectation;
}

/**
 * An executable test definition: every field of an FCAF test case, so the FCAF markdown is rendered from it, and
 * the executable steps (harness design section 4.2).
 */
export interface TestCaseDefinition {
  /** `RP_<class>_<layer>_<area>_<nnn><variant>[_UF]`; class, layer and area also give the file location. */
  id: string;
  objective: string;
  references: string[];
  /** `Profile applicability`; rendered as `None` when empty. */
  profile: IcsCondition[];
  relevancy: Relevancy;
  /** `Technology`; the section is left out when empty. */
  technology: string[];
  /** `Preconditions`; rendered as `None` when empty. */
  preconditions: string[];
  /**
   * The positive control(s) this test case depends on: it is executed only if one of them passed for the same flow.
   * Left out for a positive control. The preconditions must state it (see `preconditions.control`).
   */
  control?: string | string[];
  steps: StepDefinition[];
  /** `Comments`, one paragraph each; the section is left out when empty. */
  comments?: string[];
}

export interface TestCaseId {
  sutClass: 'WS' | 'PP' | 'AP' | 'Inf';
  layer: string;
  area: string;
  number: number;
  variant: string;
  unhappyFlow: boolean;
}

const TEST_CASE_ID = /^RP_(WS|PP|AP|Inf)_([A-Z]{2})_([A-Za-z]+)_(\d{3})([a-z]?)(_UF)?$/;

/** Parses a Relying Party test case ID, for selection and for the renderer's file layout. */
export function parseTestCaseId(id: string): TestCaseId {
  const match = TEST_CASE_ID.exec(id);
  if (!match) throw new Error(`${id} is not a Relying Party test case ID`);
  return {
    sutClass: match[1] as TestCaseId['sutClass'],
    layer: match[2],
    area: match[3],
    number: Number(match[4]),
    variant: match[5],
    unhappyFlow: Boolean(match[6]),
  };
}

/** A definition is executable when every step has an action. */
export function isExecutable(definition: TestCaseDefinition): boolean {
  return definition.steps.every((s) => s.run !== undefined);
}

/** The controls of a definition as a list. */
export function controlsOf(definition: TestCaseDefinition): string[] {
  if (!definition.control) return [];
  return Array.isArray(definition.control) ? definition.control : [definition.control];
}

const CONTROL_MENTION = /`(RP_WS_IA_MainInteraction_\d{3}[a-z]?)`/g;

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
  action: Omit<PresentationAction, 'kind' | 'statusList' | 'response'> & { statusList?: StatusListSpec | null; response?: ResponseSpec },
): PresentationAction {
  const { credential } = action;
  const withoutStatus = credential.defaultCredential === 'default_credential_pid_short' || Boolean(action.identifierList);
  const statusList =
    action.statusList === undefined ? (withoutStatus ? null : statusListToken.of(statusListFormatOf(credential.format))) : action.statusList;
  const result: PresentationAction = { kind: 'presentation', ...action, statusList, response: action.response ?? { faults: [] } };
  const faults = faultsOf(result);
  if (faults.length > 1) throw new Error(`a step applies one fault, not ${faults.join(', ')}`);
  if (result.statusList && result.statusList.format !== statusListFormatOf(credential.format)) {
    throw new Error(`a ${credential.format} credential references a Status List Token in ${statusListFormatOf(credential.format)} format`);
  }
  if (result.identifierList && credential.format !== 'mso_mdoc') throw new Error('only an mdoc references an identifier list');
  for (const [fault, point, format] of [
    ...credential.faults.map((f) => [f, 'credential', credential.format] as const),
    ...(result.statusList?.faults ?? []).map((f) => [f, 'status-list', result.statusList?.format] as const),
    ...(result.identifierList?.faults ?? []).map((f) => [f, 'identifier-list', 'cwt'] as const),
    ...result.response.faults.map((f) => [f, 'response', undefined] as const),
  ]) {
    const info = faultInfo(fault);
    if (info.point !== point) throw new Error(`fault ${fault} does not apply to the ${point}`);
    if (info.format && info.format !== format) throw new Error(`fault ${fault} applies to ${info.format}, not ${format}`);
  }
  return result;
}

/** Every fault of a presentation. */
export function faultsOf(action: StepAction): FaultId[] {
  if (action.kind !== 'presentation') return [];
  return [
    ...action.credential.faults,
    ...(action.statusList?.faults ?? []),
    ...(action.identifierList?.faults ?? []),
    ...action.response.faults,
  ];
}

/** The default query for a PID in `format`, optionally the variant restricted with `trusted_authorities`. */
export function pidQueryOf(format: CredentialFormat, options: { trustedAuthorities?: boolean } = {}): DefaultQueryId {
  const base = format === 'mso_mdoc' ? 'default_query_pid_mdoc' : 'default_query_pid';
  return (options.trustedAuthorities ? `${base}_trusted_authorities` : base) as DefaultQueryId;
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
