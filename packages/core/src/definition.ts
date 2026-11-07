import type { DefaultQueryId } from './adapter';

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

/** A credential the Test Issuers issue for a step, valid unless faults are applied. */
export interface CredentialSpec {
  /** The FCAF default credential, for example `default_credential_pid`. */
  defaultCredential: 'default_credential_pid';
  format: 'dc+sd-jwt';
  /** Entity of `default_trust_configuration_rp` that issues the credential. */
  issuer: string;
  /** Named faults; empty for a valid credential. */
  faults: string[];
}

/** A Status List Token the Test Status Provider serves for the step's credential. */
export interface StatusListSpec {
  format: 'jwt';
  /** Status value at the credential's index; 0 is VALID. */
  status: number;
  /** Entity whose revocation anchor signs the token; defaults to the credential's issuer. */
  signer?: string;
  faults: string[];
}

export interface PresentationAction {
  kind: 'presentation';
  query: DefaultQueryId;
  credential: CredentialSpec;
  statusList: StatusListSpec;
}

export type StepAction = PresentationAction;

/** Expected-result codes of the catalogue (harness design section 5). */
export type ExpectationCode = 'ACC' | 'REJ' | 'NOSTAT' | 'NOFETCH' | 'FETCHED' | 'POLICY';

/** An expected result: the codes the controller evaluates and the FCAF text it renders. */
export interface Expectation {
  codes: ExpectationCode[];
  text: string;
}

/** One line of `Test Scenario` with its line of `Expected results`, and what the harness executes for it. */
export interface StepDefinition {
  /** Test scenario text of the step. */
  text: string;
  run: StepAction;
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

export function presentation(action: Omit<PresentationAction, 'kind' | 'statusList'> & { statusList?: StatusListSpec }): PresentationAction {
  return {
    kind: 'presentation',
    ...action,
    statusList: action.statusList ?? statusListToken.jwt(),
  };
}

/** Builders for the default credentials. */
export const pid = {
  /** `default_credential_pid` in SD-JWT VC format, issued by `PP-A`. */
  sdJwtVc(options: { issuer?: string; faults?: string[] } = {}): CredentialSpec {
    return {
      defaultCredential: 'default_credential_pid',
      format: 'dc+sd-jwt',
      issuer: options.issuer ?? 'PP-A',
      faults: options.faults ?? [],
    };
  },
};

export const statusListToken = {
  /** A Status List Token in JWT format holding `status` (default 0x00, VALID) at the credential's index. */
  jwt(options: { status?: number; signer?: string; faults?: string[] } = {}): StatusListSpec {
    return { format: 'jwt', status: options.status ?? 0, signer: options.signer, faults: options.faults ?? [] };
  },
};
