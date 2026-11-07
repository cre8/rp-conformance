import type { DefaultQueryId } from './adapter';

/** Presentation flows of the Relying Party SUT. */
export type Flow = 'redirect' | 'dc-api';

/** FCAF test case verdicts. */
export type Verdict = 'PASS' | 'FAIL' | 'INCONCLUSIVE' | 'NOT APPLICABLE' | 'REVIEW';

/** A condition of the `Profile applicability` section, evaluated against the Relying Party ICS. */
export interface IcsCondition {
  /** ICS item ID, for example `RP.G.1`. */
  item: string;
  /** The text of the ICS item, as rendered in the FCAF test case. */
  text: string;
  /** The answer that makes the test case applicable. */
  equals: string;
}

/** ICS conditions used by the test definitions, named after `ics-rp.md`. */
export const ics = {
  requestsSdJwtVc: {
    item: 'RP.G.1',
    text: 'Relying Party requests credentials in IETF SD-JWT VC format.',
    equals: 'Yes',
  },
  requestsMdoc: {
    item: 'RP.G.2',
    text: 'Relying Party requests credentials in ISO/IEC 18013-5 mdoc format.',
    equals: 'Yes',
  },
  checksPidRevocation: {
    item: 'RP.R.1',
    text: 'Relying Party checks the revocation status of PIDs.',
    equals: 'Yes',
  },
} as const satisfies Record<string, IcsCondition>;

/** The ICS items that declare support for a flow. */
export const flowIcsItems: Record<Flow, string> = {
  redirect: 'RP.P.1',
  'dc-api': 'RP.P.2',
};

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

export interface Expectation {
  codes: ExpectationCode[];
}

export interface StepDefinition {
  /** Test scenario text of the step. */
  text: string;
  /** Expected result text of the step. */
  expectedText: string;
  run: StepAction;
  expect: Expectation;
}

export interface TestCaseDefinition {
  id: string;
  objective: string;
  references: string[];
  profile: IcsCondition[];
  relevancy: string;
  technology: string[];
  preconditions: string[];
  /** The positive control this test case depends on; `undefined` for a positive control itself. */
  control?: string;
  steps: StepDefinition[];
  comments?: string[];
}

export function defineTestCase(definition: TestCaseDefinition): TestCaseDefinition {
  if (definition.steps.length === 0) throw new Error(`${definition.id}: a test case needs at least one step`);
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

/** The Relying Party accepts the presentation (`ACC`). */
export const acc = (): Expectation => ({ codes: ['ACC'] });
/** The Relying Party rejects the presentation (`REJ`). */
export const rej = (): Expectation => ({ codes: ['REJ'] });
